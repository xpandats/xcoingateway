'use strict';

/**
 * Authentication Controller.
 *
 * Handles: register, login, logout, refresh, 2FA setup/verify/disable, profile.
 *
 * Security:
 *   - bcrypt password hashing (12+ rounds)
 *   - JWT access token (15 min) + HTTP-only refresh cookie (7 days)
 *   - Account lockout after 5 failed attempts
 *   - 2FA via TOTP (Google Authenticator)
 *   - Refresh token rotation (old token invalidated on use)
 *   - All actions audit-logged
 */

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { authenticator } = require('otplib');
const { User } = require('@xcg/database');
const { AuditLog } = require('@xcg/database');
const { AppError, ErrorCodes, constants, validate, schemas } = require('@xcg/common');
const { encrypt, decrypt, randomHex } = require('@xcg/crypto');
const { createLogger } = require('@xcg/logger');
const { createAuditLogger } = require('@xcg/logger');
const { config } = require('../config');

const logger = createLogger('auth');
const audit = createAuditLogger(AuditLog);

// ─── Helper: Generate JWT tokens ─────────────────────────────

function generateAccessToken(user) {
  return jwt.sign(
    {
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
      merchantId: user.merchantId?.toString() || null,
    },
    config.jwt.accessSecret,
    { expiresIn: config.jwt.accessExpiry },
  );
}

function generateRefreshToken() {
  return randomHex(32); // 64 hex chars
}

function getRefreshExpiry() {
  const days = parseInt(config.jwt.refreshExpiry, 10) || 7;
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000);
}

// ─── Helper: Set refresh token cookie ────────────────────────

function setRefreshCookie(res, token) {
  res.cookie('refreshToken', token, {
    httpOnly: true,     // Not accessible via JavaScript
    secure: config.env === 'production',   // HTTPS only in production
    sameSite: 'strict', // CSRF protection
    path: '/api/v1/auth/refresh',   // Only sent to refresh endpoint
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
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

    // Create user (default role: merchant)
    const user = await User.create({
      email: data.email,
      passwordHash,
      firstName: data.firstName,
      lastName: data.lastName,
      role: constants.ROLES.MERCHANT,
    });

    // Audit log
    await audit.log({
      actor: user._id.toString(),
      action: constants.AUDIT_ACTIONS.AUTH_REGISTER,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      resource: 'user',
      resourceId: user._id.toString(),
    });

    logger.info('User registered', { userId: user._id, email: data.email });

    res.status(201).json({
      success: true,
      data: user.toSafeJSON(),
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

    // Find user
    const user = await User.findOne({ email: data.email });
    if (!user) {
      throw AppError.unauthorized('Invalid credentials', ErrorCodes.AUTH_INVALID_CREDENTIALS);
    }

    // Check if account is disabled
    if (!user.isActive) {
      throw AppError.unauthorized('Account is disabled', ErrorCodes.AUTH_ACCOUNT_DISABLED);
    }

    // Check if account is locked
    if (user.isLocked) {
      throw AppError.unauthorized(
        'Account is locked due to too many failed attempts. Try again later.',
        ErrorCodes.AUTH_ACCOUNT_LOCKED,
      );
    }

    // Verify password
    const isValid = await bcrypt.compare(data.password, user.passwordHash);
    if (!isValid) {
      // Increment failed attempts
      user.failedLoginAttempts += 1;

      // Lock account after 5 failures
      if (user.failedLoginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + config.rateLimit.authLockoutMs);

        await audit.log({
          actor: user._id.toString(),
          action: constants.AUDIT_ACTIONS.AUTH_ACCOUNT_LOCKED,
          ip: req.ip,
          userAgent: req.get('user-agent'),
          resource: 'user',
          resourceId: user._id.toString(),
          metadata: { reason: 'Too many failed login attempts' },
        });
      }

      await user.save();

      await audit.log({
        actor: user._id.toString(),
        action: constants.AUDIT_ACTIONS.AUTH_LOGIN_FAILED,
        ip: req.ip,
        userAgent: req.get('user-agent'),
        resource: 'user',
        resourceId: user._id.toString(),
      });

      throw AppError.unauthorized('Invalid credentials', ErrorCodes.AUTH_INVALID_CREDENTIALS);
    }

    // Check 2FA if enabled
    if (user.twoFactorEnabled) {
      if (!data.totpCode) {
        throw AppError.unauthorized('2FA code required', ErrorCodes.AUTH_2FA_REQUIRED);
      }

      // Decrypt 2FA secret
      const secret = decrypt(user.twoFactorSecret);
      const isValidTotp = authenticator.verify({ token: data.totpCode, secret });

      if (!isValidTotp) {
        throw AppError.unauthorized('Invalid 2FA code', ErrorCodes.AUTH_2FA_INVALID);
      }
    }

    // Reset failed attempts on successful login
    user.failedLoginAttempts = 0;
    user.lockUntil = null;
    user.lastLoginAt = new Date();
    user.lastLoginIp = req.ip;

    // Generate tokens
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken();
    const refreshTokenHash = await bcrypt.hash(refreshToken, 10);

    // Store refresh token (limit to 5 active sessions)
    if (user.refreshTokens.length >= 5) {
      user.refreshTokens.shift(); // Remove oldest
    }

    user.refreshTokens.push({
      tokenHash: refreshTokenHash,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      expiresAt: getRefreshExpiry(),
    });

    await user.save();

    // Set refresh token in HTTP-only cookie
    setRefreshCookie(res, refreshToken);

    // Audit log
    await audit.log({
      actor: user._id.toString(),
      action: constants.AUDIT_ACTIONS.AUTH_LOGIN_SUCCESS,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      resource: 'user',
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
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken) {
      // Remove the specific refresh token
      const user = await User.findById(req.user.userId);
      if (user) {
        // Find and remove matching token
        const tokensBefore = user.refreshTokens.length;
        user.refreshTokens = user.refreshTokens.filter((rt) => {
          return !bcrypt.compareSync(refreshToken, rt.tokenHash);
        });
        if (user.refreshTokens.length !== tokensBefore) {
          await user.save();
        }
      }
    }

    clearRefreshCookie(res);

    await audit.log({
      actor: req.user.userId,
      action: constants.AUDIT_ACTIONS.AUTH_LOGOUT,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      resource: 'user',
      resourceId: req.user.userId,
    });

    res.json({ success: true, message: 'Logged out successfully' });

  } catch (err) {
    next(err);
  }
};

// ═════════════════════════════════════════════════════════════
// REFRESH TOKEN
// ═════════════════════════════════════════════════════════════

exports.refresh = async (req, res, next) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      throw AppError.unauthorized('Refresh token required', ErrorCodes.AUTH_REFRESH_INVALID);
    }

    // Find user with matching refresh token
    const users = await User.find({ 'refreshTokens.0': { $exists: true } });
    let matchedUser = null;
    let matchedTokenIndex = -1;

    for (const user of users) {
      for (let i = 0; i < user.refreshTokens.length; i++) {
        const rt = user.refreshTokens[i];
        if (await bcrypt.compare(refreshToken, rt.tokenHash)) {
          // Check if expired
          if (rt.expiresAt < new Date()) {
            user.refreshTokens.splice(i, 1);
            await user.save();
            throw AppError.unauthorized('Refresh token expired', ErrorCodes.AUTH_REFRESH_EXPIRED);
          }
          matchedUser = user;
          matchedTokenIndex = i;
          break;
        }
      }
      if (matchedUser) break;
    }

    if (!matchedUser) {
      throw AppError.unauthorized('Invalid refresh token', ErrorCodes.AUTH_REFRESH_INVALID);
    }

    if (!matchedUser.isActive) {
      throw AppError.unauthorized('Account is disabled', ErrorCodes.AUTH_ACCOUNT_DISABLED);
    }

    // Token rotation: remove old, create new
    matchedUser.refreshTokens.splice(matchedTokenIndex, 1);

    const newAccessToken = generateAccessToken(matchedUser);
    const newRefreshToken = generateRefreshToken();
    const newRefreshTokenHash = await bcrypt.hash(newRefreshToken, 10);

    matchedUser.refreshTokens.push({
      tokenHash: newRefreshTokenHash,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      expiresAt: getRefreshExpiry(),
    });

    await matchedUser.save();

    // Set new refresh token cookie
    setRefreshCookie(res, newRefreshToken);

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
// GET ME (Profile)
// ═════════════════════════════════════════════════════════════

exports.me = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.userId).select('-refreshTokens -passwordHash -twoFactorSecret');
    if (!user) {
      throw AppError.notFound('User not found');
    }

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

    // Encrypt and store (not enabled yet — user must verify first)
    user.twoFactorSecret = encrypt(secret);
    await user.save();

    res.json({
      success: true,
      data: {
        secret,      // Show to user once (they'll enter it in their authenticator app)
        otpAuthUrl,  // QR code URI
        message: 'Scan QR code with your authenticator app, then verify with a code',
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
      throw AppError.badRequest('2FA setup not initiated. Call /2fa/setup first.');
    }

    // Decrypt and verify
    const secret = decrypt(user.twoFactorSecret);
    const isValid = authenticator.verify({ token: data.totpCode, secret });

    if (!isValid) {
      throw AppError.unauthorized('Invalid 2FA code', ErrorCodes.AUTH_2FA_INVALID);
    }

    // Enable 2FA
    user.twoFactorEnabled = true;
    await user.save();

    await audit.log({
      actor: req.user.userId,
      action: constants.AUDIT_ACTIONS.AUTH_2FA_ENABLED,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      resource: 'user',
      resourceId: req.user.userId,
    });

    logger.info('2FA enabled', { userId: req.user.userId });

    res.json({
      success: true,
      message: '2FA enabled successfully',
    });

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

    // Verify current code before disabling
    const secret = decrypt(user.twoFactorSecret);
    const isValid = authenticator.verify({ token: data.totpCode, secret });

    if (!isValid) {
      throw AppError.unauthorized('Invalid 2FA code', ErrorCodes.AUTH_2FA_INVALID);
    }

    user.twoFactorEnabled = false;
    user.twoFactorSecret = null;
    await user.save();

    await audit.log({
      actor: req.user.userId,
      action: constants.AUDIT_ACTIONS.AUTH_2FA_DISABLED,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      resource: 'user',
      resourceId: req.user.userId,
    });

    logger.info('2FA disabled', { userId: req.user.userId });

    res.json({
      success: true,
      message: '2FA disabled successfully',
    });

  } catch (err) {
    next(err);
  }
};
