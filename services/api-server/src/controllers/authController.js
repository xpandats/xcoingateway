'use strict';

/**
 * Authentication Controller — Commercial Grade.
 *
 * Handles: register, login, logout, refresh, changePassword,
 *          2FA setup/verify/disable, profile.
 *
 * Security features:
 *   - bcrypt password hashing (12+ rounds)
 *   - JWT access token (15 min) + HTTP-only refresh cookie (7 days)
 *   - Account lockout after 5 failed attempts (auto-reset on expiry)
 *   - 2FA via TOTP with replay prevention (each code used only once)
 *   - Refresh token rotation with family tracking (stolen token detection)
 *   - Password history (prevent reuse of last 5 passwords)
 *   - Admin approval required for merchant accounts
 *   - All actions audit-logged with requestId correlation
 */

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { authenticator } = require('otplib');
const { User, RefreshToken, UsedTotpCode, AuditLog } = require('@xcg/database');
const { AppError, ErrorCodes, constants, validate, schemas } = require('@xcg/common');
const { encrypt, decrypt, randomHex } = require('@xcg/crypto');
const { createLogger, createAuditLogger } = require('@xcg/logger');
const { config } = require('../config');

const logger = createLogger('auth');
const audit = createAuditLogger(AuditLog);

// Max active refresh tokens per user (limits concurrent sessions)
const MAX_SESSIONS_PER_USER = 5;
const PASSWORD_HISTORY_SIZE = 5;

// ─── Helper: Generate JWT access token ───────────────────────

function generateAccessToken(user) {
  return jwt.sign(
    {
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
      merchantId: user.merchantId?.toString() || null,
    },
    config.jwt.accessSecret,
    { expiresIn: config.jwt.accessExpiry, algorithm: 'HS256' },
  );
}

// ─── Helper: Refresh token ──────────────────────────────────

function generateRefreshTokenValue() {
  return randomHex(32); // 64 hex chars = 256 bits of entropy
}

function hashRefreshToken(token) {
  // Use SHA-256 for refresh tokens (faster than bcrypt, sufficient for random tokens)
  return crypto.createHash('sha256').update(token).digest('hex');
}

function getRefreshExpiryDate() {
  const days = parseInt(config.jwt.refreshExpiry, 10) || 7;
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000);
}

// ─── Helper: Refresh cookie ─────────────────────────────────

function setRefreshCookie(res, token) {
  res.cookie('refreshToken', token, {
    httpOnly: true,
    secure: config.env === 'production',
    sameSite: 'strict',
    path: '/api/v1/auth/refresh',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

function clearRefreshCookie(res) {
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: config.env === 'production',
    sameSite: 'strict',
    path: '/api/v1/auth/refresh',
  });
}

// ─── Helper: Audit log with requestId ───────────────────────

async function auditLog(req, action, extra = {}) {
  await audit.log({
    actor: extra.actor || req.user?.userId || 'anonymous',
    action,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    resource: extra.resource || 'user',
    resourceId: extra.resourceId || req.user?.userId || null,
    before: extra.before || null,
    after: extra.after || null,
    metadata: { requestId: req.requestId, ...extra.metadata },
  });
}

// ─── Helper: Validate TOTP with replay prevention ───────────

async function validateTOTP(userId, code, encryptedSecret) {
  const secret = decrypt(encryptedSecret);
  const isValid = authenticator.verify({ token: code, secret });

  if (!isValid) {
    return false;
  }

  // Check if code was already used (replay prevention)
  try {
    await UsedTotpCode.create({ userId, code, usedAt: new Date() });
    return true;
  } catch (err) {
    // Duplicate key error = code already used within TTL window
    if (err.code === 11000) {
      return false;
    }
    throw err;
  }
}

// ═════════════════════════════════════════════════════════════
// REGISTER
// ═════════════════════════════════════════════════════════════

exports.register = async (req, res, next) => {
  try {
    const data = validate(schemas.auth.register, req.body);

    // Check if email already exists
    const existingUser = await User.findOne({ email: data.email });
    if (existingUser) {
      throw AppError.conflict('Email already registered', ErrorCodes.VALIDATION_FAILED);
    }

    // Hash password
    const passwordHash = await bcrypt.hash(data.password, config.bcrypt.saltRounds);

    // Create user
    // - Default role: merchant
    // - isApproved: false (admin must approve before merchant can operate)
    // - Store initial password in history
    const user = await User.create({
      email: data.email,
      passwordHash,
      firstName: data.firstName,
      lastName: data.lastName,
      role: constants.ROLES.MERCHANT,
      isApproved: false,
      passwordHistory: [passwordHash],
    });

    await auditLog(req, constants.AUDIT_ACTIONS.AUTH_REGISTER, {
      actor: user._id.toString(),
      resourceId: user._id.toString(),
    });

    logger.info('User registered (pending approval)', { userId: user._id, email: data.email });

    res.status(201).json({
      success: true,
      data: user.toSafeJSON(),
      message: 'Account created. Pending admin approval before you can operate.',
    });

  } catch (err) {
    next(err);
  }
};

// ═════════════════════════════════════════════════════════════
// LOGIN
// ═════════════════════════════════════════════════════════════

exports.login = async (req, res, next) => {
  try {
    const data = validate(schemas.auth.login, req.body);

    // Find user (include passwordHash for comparison)
    const user = await User.findOne({ email: data.email });
    if (!user) {
      // Same error message for wrong email vs wrong password (prevent enumeration)
      throw AppError.unauthorized('Invalid credentials', ErrorCodes.AUTH_INVALID_CREDENTIALS);
    }

    // Check if account is disabled
    if (!user.isActive) {
      await auditLog(req, constants.AUDIT_ACTIONS.AUTH_LOGIN_FAILED, {
        actor: user._id.toString(),
        resourceId: user._id.toString(),
        metadata: { reason: 'account_disabled' },
      });
      throw AppError.unauthorized('Account is disabled', ErrorCodes.AUTH_ACCOUNT_DISABLED);
    }

    // Check if account is locked
    if (user.lockUntil && user.lockUntil > Date.now()) {
      await auditLog(req, constants.AUDIT_ACTIONS.AUTH_LOGIN_FAILED, {
        actor: user._id.toString(),
        resourceId: user._id.toString(),
        metadata: { reason: 'account_locked' },
      });
      throw AppError.unauthorized(
        'Account is locked due to too many failed attempts. Try again later.',
        ErrorCodes.AUTH_ACCOUNT_LOCKED,
      );
    }

    // If lock has expired, reset attempts
    if (user.lockUntil && user.lockUntil <= Date.now()) {
      user.failedLoginAttempts = 0;
      user.lockUntil = null;
    }

    // Verify password
    const isValid = await bcrypt.compare(data.password, user.passwordHash);
    if (!isValid) {
      user.failedLoginAttempts += 1;

      if (user.failedLoginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + config.rateLimit.authLockoutMs);

        await auditLog(req, constants.AUDIT_ACTIONS.AUTH_ACCOUNT_LOCKED, {
          actor: user._id.toString(),
          resourceId: user._id.toString(),
          metadata: { attempts: user.failedLoginAttempts },
        });

        logger.warn('Account locked', { userId: user._id, attempts: user.failedLoginAttempts });
      }

      await user.save();

      await auditLog(req, constants.AUDIT_ACTIONS.AUTH_LOGIN_FAILED, {
        actor: user._id.toString(),
        resourceId: user._id.toString(),
        metadata: { reason: 'invalid_password', attempts: user.failedLoginAttempts },
      });

      throw AppError.unauthorized('Invalid credentials', ErrorCodes.AUTH_INVALID_CREDENTIALS);
    }

    // Check 2FA if enabled
    if (user.twoFactorEnabled) {
      if (!data.totpCode) {
        throw AppError.unauthorized('2FA code required', ErrorCodes.AUTH_2FA_REQUIRED);
      }

      const isValidTotp = await validateTOTP(user._id, data.totpCode, user.twoFactorSecret);
      if (!isValidTotp) {
        throw AppError.unauthorized('Invalid or already used 2FA code', ErrorCodes.AUTH_2FA_INVALID);
      }
    }

    // ── Login success ──

    // Reset failed attempts
    user.failedLoginAttempts = 0;
    user.lockUntil = null;
    user.lastLoginAt = new Date();
    user.lastLoginIp = req.ip;
    await user.save();

    // Generate tokens
    const accessToken = generateAccessToken(user);
    const refreshTokenValue = generateRefreshTokenValue();
    const refreshTokenHash = hashRefreshToken(refreshTokenValue);
    const tokenFamily = randomHex(16); // Family for reuse detection

    // Enforce max sessions: remove oldest if at limit
    const activeTokenCount = await RefreshToken.countDocuments({
      userId: user._id,
      isRevoked: false,
      expiresAt: { $gt: new Date() },
    });

    if (activeTokenCount >= MAX_SESSIONS_PER_USER) {
      // Revoke oldest session
      const oldest = await RefreshToken.findOne({
        userId: user._id,
        isRevoked: false,
      }).sort({ createdAt: 1 });

      if (oldest) {
        oldest.isRevoked = true;
        oldest.revokedAt = new Date();
        await oldest.save();
      }
    }

    // Store refresh token
    await RefreshToken.create({
      userId: user._id,
      tokenHash: refreshTokenHash,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      expiresAt: getRefreshExpiryDate(),
      family: tokenFamily,
    });

    // Set refresh token cookie
    setRefreshCookie(res, refreshTokenValue);

    // Audit
    await auditLog(req, constants.AUDIT_ACTIONS.AUTH_LOGIN_SUCCESS, {
      actor: user._id.toString(),
      resourceId: user._id.toString(),
    });

    logger.info('User logged in', { userId: user._id, email: data.email });

    res.json({
      success: true,
      data: {
        user: user.toSafeJSON(),
        accessToken,
        expiresIn: config.jwt.accessExpiry,
      },
    });

  } catch (err) {
    next(err);
  }
};

// ═════════════════════════════════════════════════════════════
// LOGOUT
// ═════════════════════════════════════════════════════════════

exports.logout = async (req, res, next) => {
  try {
    const refreshTokenValue = req.cookies.refreshToken;

    if (refreshTokenValue) {
      const tokenHash = hashRefreshToken(refreshTokenValue);
      // Revoke the specific token (O(1) lookup via indexed hash)
      await RefreshToken.updateOne(
        { tokenHash, isRevoked: false },
        { $set: { isRevoked: true, revokedAt: new Date() } },
      );
    }

    clearRefreshCookie(res);

    await auditLog(req, constants.AUDIT_ACTIONS.AUTH_LOGOUT);

    res.json({ success: true, message: 'Logged out successfully' });

  } catch (err) {
    next(err);
  }
};

// ═════════════════════════════════════════════════════════════
// LOGOUT ALL SESSIONS
// ═════════════════════════════════════════════════════════════

exports.logoutAll = async (req, res, next) => {
  try {
    // Revoke ALL refresh tokens for this user
    await RefreshToken.updateMany(
      { userId: req.user.userId, isRevoked: false },
      { $set: { isRevoked: true, revokedAt: new Date() } },
    );

    clearRefreshCookie(res);

    await auditLog(req, constants.AUDIT_ACTIONS.AUTH_LOGOUT, {
      metadata: { scope: 'all_sessions' },
    });

    res.json({ success: true, message: 'All sessions terminated' });

  } catch (err) {
    next(err);
  }
};

// ═════════════════════════════════════════════════════════════
// REFRESH TOKEN
// ═════════════════════════════════════════════════════════════

exports.refresh = async (req, res, next) => {
  try {
    const refreshTokenValue = req.cookies.refreshToken;
    if (!refreshTokenValue) {
      throw AppError.unauthorized('Refresh token required', ErrorCodes.AUTH_REFRESH_INVALID);
    }

    const tokenHash = hashRefreshToken(refreshTokenValue);

    // O(1) lookup via indexed tokenHash (not a full user scan)
    const storedToken = await RefreshToken.findOne({ tokenHash });

    if (!storedToken) {
      throw AppError.unauthorized('Invalid refresh token', ErrorCodes.AUTH_REFRESH_INVALID);
    }

    // Check if token was revoked
    if (storedToken.isRevoked) {
      // SECURITY: If a revoked token is used, it means either:
      // 1. The token was stolen and the real user already rotated it
      // 2. An attacker is using a previously-valid token
      // → Revoke the ENTIRE family to protect the user
      logger.warn('Revoked refresh token reuse detected — revoking entire family', {
        userId: storedToken.userId,
        family: storedToken.family,
      });

      await RefreshToken.updateMany(
        { family: storedToken.family },
        { $set: { isRevoked: true, revokedAt: new Date() } },
      );

      await auditLog(req, constants.AUDIT_ACTIONS.AUTH_LOGIN_FAILED, {
        actor: storedToken.userId.toString(),
        resourceId: storedToken.userId.toString(),
        metadata: { reason: 'refresh_token_reuse', family: storedToken.family },
      });

      throw AppError.unauthorized('Token reuse detected. All sessions revoked.', ErrorCodes.AUTH_REFRESH_INVALID);
    }

    // Check if expired
    if (storedToken.expiresAt < new Date()) {
      storedToken.isRevoked = true;
      storedToken.revokedAt = new Date();
      await storedToken.save();
      throw AppError.unauthorized('Refresh token expired', ErrorCodes.AUTH_REFRESH_EXPIRED);
    }

    // Verify user is still active
    const user = await User.findById(storedToken.userId);
    if (!user || !user.isActive) {
      storedToken.isRevoked = true;
      storedToken.revokedAt = new Date();
      await storedToken.save();
      throw AppError.unauthorized('Account is disabled', ErrorCodes.AUTH_ACCOUNT_DISABLED);
    }

    // ── Token rotation ──

    // Revoke the old token
    storedToken.isRevoked = true;
    storedToken.revokedAt = new Date();

    // Create new token in the same family
    const newRefreshTokenValue = generateRefreshTokenValue();
    const newTokenHash = hashRefreshToken(newRefreshTokenValue);

    storedToken.replacedByToken = newTokenHash;
    await storedToken.save();

    await RefreshToken.create({
      userId: user._id,
      tokenHash: newTokenHash,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      expiresAt: getRefreshExpiryDate(),
      family: storedToken.family, // Same family for reuse detection
    });

    // Generate new access token
    const newAccessToken = generateAccessToken(user);

    // Set new refresh token cookie
    setRefreshCookie(res, newRefreshTokenValue);

    res.json({
      success: true,
      data: {
        accessToken: newAccessToken,
        expiresIn: config.jwt.accessExpiry,
      },
    });

  } catch (err) {
    next(err);
  }
};

// ═════════════════════════════════════════════════════════════
// CHANGE PASSWORD
// ═════════════════════════════════════════════════════════════

exports.changePassword = async (req, res, next) => {
  try {
    const data = validate(schemas.auth.changePassword, req.body);

    const user = await User.findById(req.user.userId);
    if (!user) throw AppError.notFound('User not found');

    // Verify current password
    const isValid = await bcrypt.compare(data.currentPassword, user.passwordHash);
    if (!isValid) {
      throw AppError.unauthorized('Current password is incorrect', ErrorCodes.AUTH_INVALID_CREDENTIALS);
    }

    // Check new password is not same as current
    if (data.currentPassword === data.newPassword) {
      throw AppError.badRequest('New password must be different from current password');
    }

    // Check password history (prevent reuse of last 5)
    if (user.passwordHistory && user.passwordHistory.length > 0) {
      for (const oldHash of user.passwordHistory) {
        const isReused = await bcrypt.compare(data.newPassword, oldHash);
        if (isReused) {
          throw AppError.badRequest('Cannot reuse any of your last 5 passwords');
        }
      }
    }

    // Hash new password
    const newHash = await bcrypt.hash(data.newPassword, config.bcrypt.saltRounds);

    // Update user
    const oldHash = user.passwordHash;
    user.passwordHash = newHash;
    user.passwordChangedAt = new Date();

    // Update password history (keep last 5)
    if (!user.passwordHistory) user.passwordHistory = [];
    user.passwordHistory.push(newHash);
    if (user.passwordHistory.length > PASSWORD_HISTORY_SIZE) {
      user.passwordHistory = user.passwordHistory.slice(-PASSWORD_HISTORY_SIZE);
    }

    await user.save();

    // Revoke all refresh tokens (force re-login on all devices)
    await RefreshToken.updateMany(
      { userId: user._id, isRevoked: false },
      { $set: { isRevoked: true, revokedAt: new Date() } },
    );

    clearRefreshCookie(res);

    await auditLog(req, constants.AUDIT_ACTIONS.AUTH_PASSWORD_CHANGED, {
      metadata: { allSessionsRevoked: true },
    });

    logger.info('Password changed', { userId: req.user.userId });

    res.json({
      success: true,
      message: 'Password changed. All sessions have been terminated. Please log in again.',
    });

  } catch (err) {
    next(err);
  }
};

// ═════════════════════════════════════════════════════════════
// GET ME (Profile)
// ═════════════════════════════════════════════════════════════

exports.me = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) throw AppError.notFound('User not found');

    res.json({
      success: true,
      data: user.toSafeJSON(),
    });

  } catch (err) {
    next(err);
  }
};

// ═════════════════════════════════════════════════════════════
// 2FA SETUP
// ═════════════════════════════════════════════════════════════

exports.setup2FA = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) throw AppError.notFound('User not found');

    if (user.twoFactorEnabled) {
      throw AppError.conflict('2FA is already enabled', ErrorCodes.AUTH_2FA_ALREADY_ENABLED);
    }

    // Generate TOTP secret
    const secret = authenticator.generateSecret();
    const otpAuthUrl = authenticator.keyuri(user.email, 'XCoinGateway', secret);

    // Encrypt and store (not enabled yet — user must verify with a code first)
    user.twoFactorSecret = encrypt(secret);
    await user.save();

    res.json({
      success: true,
      data: {
        secret,      // Shown ONCE — user enters in their authenticator app
        otpAuthUrl,  // QR code URI for scanning
        warning: 'Save this secret securely. It will NOT be shown again.',
      },
    });

  } catch (err) {
    next(err);
  }
};

// ═════════════════════════════════════════════════════════════
// 2FA VERIFY (Enable)
// ═════════════════════════════════════════════════════════════

exports.verify2FA = async (req, res, next) => {
  try {
    const data = validate(schemas.auth.verify2fa, req.body);

    const user = await User.findById(req.user.userId);
    if (!user) throw AppError.notFound('User not found');

    if (user.twoFactorEnabled) {
      throw AppError.conflict('2FA is already enabled', ErrorCodes.AUTH_2FA_ALREADY_ENABLED);
    }

    if (!user.twoFactorSecret) {
      throw AppError.badRequest('2FA setup not initiated. Call POST /2fa/setup first.');
    }

    // Validate with replay prevention
    const isValid = await validateTOTP(user._id, data.totpCode, user.twoFactorSecret);
    if (!isValid) {
      throw AppError.unauthorized('Invalid or already used 2FA code', ErrorCodes.AUTH_2FA_INVALID);
    }

    // Enable 2FA
    user.twoFactorEnabled = true;
    await user.save();

    await auditLog(req, constants.AUDIT_ACTIONS.AUTH_2FA_ENABLED);

    logger.info('2FA enabled', { userId: req.user.userId });

    res.json({ success: true, message: '2FA enabled successfully' });

  } catch (err) {
    next(err);
  }
};

// ═════════════════════════════════════════════════════════════
// 2FA DISABLE
// ═════════════════════════════════════════════════════════════

exports.disable2FA = async (req, res, next) => {
  try {
    const data = validate(schemas.auth.verify2fa, req.body);

    const user = await User.findById(req.user.userId);
    if (!user) throw AppError.notFound('User not found');

    if (!user.twoFactorEnabled) {
      throw AppError.badRequest('2FA is not enabled');
    }

    // Verify current code before disabling (with replay prevention)
    const isValid = await validateTOTP(user._id, data.totpCode, user.twoFactorSecret);
    if (!isValid) {
      throw AppError.unauthorized('Invalid or already used 2FA code', ErrorCodes.AUTH_2FA_INVALID);
    }

    user.twoFactorEnabled = false;
    user.twoFactorSecret = null;
    await user.save();

    await auditLog(req, constants.AUDIT_ACTIONS.AUTH_2FA_DISABLED);

    logger.info('2FA disabled', { userId: req.user.userId });

    res.json({ success: true, message: '2FA disabled successfully' });

  } catch (err) {
    next(err);
  }
};
