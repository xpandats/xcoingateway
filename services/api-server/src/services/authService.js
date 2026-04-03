'use strict';

/**
 * @module services/api-server/services/authService
 *
 * Authentication Service — Bank-Grade Business Logic.
 *
 * This service owns ALL authentication business logic.
 * The controller (HTTP layer) is a thin wrapper that:
 *   1. Validates input (via Joi)
 *   2. Calls service methods
 *   3. Returns standardized responses
 *
 * SEPARATION OF CONCERNS:
 *   Controller = HTTP (req/res/status codes)
 *   Service    = Business logic (users, tokens, crypto)
 *   Model      = Data access (MongoDB)
 *
 * TRANSACTION SAFETY:
 *   Multi-document operations use MongoDB sessions/transactions
 *   to ensure atomicity. If any step fails, ALL changes are rolled back.
 */

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const mongoose = require('mongoose');
const { authenticator } = require('otplib');
const { User, RefreshToken, UsedTotpCode, AuditLog } = require('@xcg/database');
const { AppError, ErrorCodes, constants, getRequestContext, validateObjectId } = require('@xcg/common');
const { encrypt, decrypt, randomHex } = require('@xcg/crypto');
const { createLogger, createAuditLogger } = require('@xcg/logger');
const { config } = require('../config');

const logger = createLogger('auth-service');
const audit = createAuditLogger(AuditLog);
const { AUTH, ROLES, AUDIT_ACTIONS } = constants;

// ═══════════════════════════════════════════════════════════════
// INTERNAL HELPERS — Pure functions, no HTTP dependency
// ═══════════════════════════════════════════════════════════════

/**
 * Generate a signed JWT access token.
 * @param {object} user - Mongoose User document
 * @returns {string} Signed JWT
 */
function _generateAccessToken(user) {
  return jwt.sign(
    {
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
      merchantId: user.merchantId?.toString() || null,
      jti: randomHex(16), // Unique token ID for future revocation
    },
    config.jwt.accessSecret,
    { expiresIn: config.jwt.accessExpiry, algorithm: 'HS256' },
  );
}

/**
 * Generate a cryptographically random refresh token value.
 * @returns {string} 64 hex chars (256 bits entropy)
 */
function _generateRefreshTokenValue() {
  return randomHex(32);
}

/**
 * Hash a refresh token for storage.
 * SHA-256 is sufficient for random tokens (not passwords).
 * @param {string} token - Raw refresh token
 * @returns {string} SHA-256 hex hash
 */
function _hashRefreshToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Calculate refresh token expiry date.
 * @returns {Date} Expiry timestamp
 */
function _getRefreshExpiryDate() {
  const days = parseInt(config.jwt.refreshExpiry, 10) || 7;
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000);
}

/**
 * Write an audit log entry with automatic context enrichment.
 * Non-blocking — audit failures never crash business logic.
 *
 * @param {string} action - From AUDIT_ACTIONS constants
 * @param {object} fields - Audit fields
 */
async function _audit(action, fields = {}) {
  const ctx = getRequestContext();
  try {
    await audit.log({
      actor: fields.actor || ctx.userId || 'anonymous',
      action,
      ip: fields.ip || ctx.ip || null,
      userAgent: fields.userAgent || ctx.userAgent || null,
      resource: fields.resource || 'user',
      resourceId: fields.resourceId || ctx.userId || null,
      before: fields.before || null,
      after: fields.after || null,
      metadata: { requestId: ctx.requestId, ...fields.metadata },
    });
  } catch (err) {
    logger.error('Audit log write failed', { error: err.message, action });
  }
}

/**
 * Validate TOTP code with replay prevention.
 * Each code can only be used ONCE within its TTL window.
 *
 * @param {string} userId - User's MongoDB ObjectId
 * @param {string} code - 6-digit TOTP code
 * @param {string} encryptedSecret - AES-encrypted TOTP secret
 * @returns {boolean} true if valid and not replayed
 */
async function _validateTOTP(userId, code, encryptedSecret) {
  const secret = decrypt(encryptedSecret);
  const isValid = authenticator.verify({ token: code, secret });

  if (!isValid) return false;

  try {
    await UsedTotpCode.create({ userId, code, usedAt: new Date() });
    return true;
  } catch (err) {
    if (err.code === 11000) return false; // Already used
    throw err;
  }
}

// ═══════════════════════════════════════════════════════════════
// PUBLIC SERVICE METHODS
// ═══════════════════════════════════════════════════════════════

/**
 * Register a new merchant account.
 *
 * @param {object} data - Validated registration data
 * @param {string} data.email
 * @param {string} data.password
 * @param {string} data.firstName
 * @param {string} data.lastName
 * @returns {{ user: object, isNew: boolean }}
 */
async function register(data) {
  // SECURITY: Check for existing email but return same response shape
  // to prevent account enumeration attacks.
  const existingUser = await User.findOne({ email: data.email });
  if (existingUser) {
    logger.warn('Registration attempt for existing email', {
      email: data.email,
      ip: getRequestContext().ip,
    });
    return { user: null, isNew: false };
  }

  const passwordHash = await bcrypt.hash(data.password, config.bcrypt.saltRounds);

  const user = await User.create({
    email: data.email,
    passwordHash,
    firstName: data.firstName,
    lastName: data.lastName,
    role: ROLES.MERCHANT,
    isApproved: false,
    passwordHistory: [passwordHash],
  });

  await _audit(AUDIT_ACTIONS.AUTH_REGISTER, {
    actor: user._id.toString(),
    resourceId: user._id.toString(),
  });

  logger.info('User registered (pending approval)', { userId: user._id });
  return { user, isNew: true };
}

/**
 * Authenticate a user and create session tokens.
 *
 * @param {object} data - Validated login data
 * @param {string} data.email
 * @param {string} data.password
 * @param {string} [data.totpCode]
 * @param {string} ip - Client IP
 * @param {string} userAgent - Client user agent
 * @returns {{ user: object, accessToken: string, refreshToken: string }}
 */
async function login(data, ip, userAgent) {
  // SECURITY: fetch with sensitive fields explicitly for password comparison
  const user = await User.findOne({ email: data.email }).select(
    '+passwordHash +twoFactorSecret',
  );

  // Same error for wrong email vs wrong password (anti-enumeration)
  if (!user) {
    throw AppError.unauthorized('Invalid credentials', ErrorCodes.AUTH_INVALID_CREDENTIALS);
  }

  if (!user.isActive) {
    await _audit(AUDIT_ACTIONS.AUTH_LOGIN_FAILED, {
      actor: user._id.toString(),
      resourceId: user._id.toString(),
      metadata: { reason: 'account_disabled' },
    });
    throw AppError.unauthorized('Account is disabled', ErrorCodes.AUTH_ACCOUNT_DISABLED);
  }

  // A4: Use isLocked virtual (single consistent code path)
  if (user.isLocked) {
    await _audit(AUDIT_ACTIONS.AUTH_LOGIN_FAILED, {
      actor: user._id.toString(),
      resourceId: user._id.toString(),
      metadata: { reason: 'account_locked' },
    });
    throw AppError.unauthorized(
      'Account is locked due to too many failed attempts. Try again later.',
      ErrorCodes.AUTH_ACCOUNT_LOCKED,
    );
  }

  // A8: Clear expired lock and audit it
  if (user.lockUntil && user.lockUntil <= Date.now()) {
    user.failedLoginAttempts = 0;
    user.lockUntil = null;
    await _audit(AUDIT_ACTIONS.AUTH_ACCOUNT_UNLOCKED, {
      actor: user._id.toString(),
      resourceId: user._id.toString(),
      metadata: { reason: 'lock_expired' },
    });
  }

  // Verify password
  const isValid = await bcrypt.compare(data.password, user.passwordHash);
  if (!isValid) {
    user.failedLoginAttempts += 1;

    if (user.failedLoginAttempts >= AUTH.MAX_FAILED_ATTEMPTS) {
      user.lockUntil = new Date(Date.now() + config.rateLimit.authLockoutMs);
      await _audit(AUDIT_ACTIONS.AUTH_ACCOUNT_LOCKED, {
        actor: user._id.toString(),
        resourceId: user._id.toString(),
        metadata: { attempts: user.failedLoginAttempts },
      });
      logger.warn('Account locked', { userId: user._id, attempts: user.failedLoginAttempts });
    }

    await user.save();

    await _audit(AUDIT_ACTIONS.AUTH_LOGIN_FAILED, {
      actor: user._id.toString(),
      resourceId: user._id.toString(),
      metadata: { reason: 'invalid_password', attempts: user.failedLoginAttempts },
    });

    throw AppError.unauthorized('Invalid credentials', ErrorCodes.AUTH_INVALID_CREDENTIALS);
  }

  // 2FA verification
  if (user.twoFactorEnabled) {
    if (!data.totpCode) {
      throw AppError.unauthorized('2FA code required', ErrorCodes.AUTH_2FA_REQUIRED);
    }
    const isValidTotp = await _validateTOTP(user._id, data.totpCode, user.twoFactorSecret);
    if (!isValidTotp) {
      throw AppError.unauthorized('Invalid or already used 2FA code', ErrorCodes.AUTH_2FA_INVALID);
    }
  }

  // ── Success: reset attempts, create tokens ──

  user.failedLoginAttempts = 0;
  user.lockUntil = null;
  user.lastLoginAt = new Date();
  // Hash IP for privacy (GDPR) — SHA-256 of IP is still useful for security analysis
  user.lastLoginIp = crypto.createHash('sha256').update(ip || '').digest('hex').slice(0, 16);
  await user.save();

  const accessToken = _generateAccessToken(user);
  const refreshTokenValue = _generateRefreshTokenValue();
  const refreshTokenHash = _hashRefreshToken(refreshTokenValue);
  const tokenFamily = randomHex(16);

  // D1: ATOMIC session management — evict + create in one transaction
  const session = await mongoose.startSession();
  try {
    await session.withTransaction(async () => {
      const activeTokenCount = await RefreshToken.countDocuments(
        { userId: user._id, isRevoked: false, expiresAt: { $gt: new Date() } },
        { session },
      );

      if (activeTokenCount >= AUTH.MAX_SESSIONS_PER_USER) {
        const oldest = await RefreshToken.findOne(
          { userId: user._id, isRevoked: false },
          null,
          { session },
        ).sort({ createdAt: 1 });

        if (oldest) {
          await RefreshToken.updateOne(
            { _id: oldest._id },
            { $set: { isRevoked: true, revokedAt: new Date() } },
            { session },
          );
        }
      }

      await RefreshToken.create([{
        userId: user._id,
        tokenHash: refreshTokenHash,
        ip,
        userAgent,
        expiresAt: _getRefreshExpiryDate(),
        family: tokenFamily,
      }], { session });
    });
  } finally {
    await session.endSession();
  }

  await _audit(AUDIT_ACTIONS.AUTH_LOGIN_SUCCESS, {
    actor: user._id.toString(),
    resourceId: user._id.toString(),
  });

  logger.info('User logged in', { userId: user._id });

  return { user, accessToken, refreshToken: refreshTokenValue };
}

/**
 * Logout: revoke a specific refresh token.
 *
 * @param {string|null} refreshTokenValue - Raw refresh token from cookie
 * @param {string} userId - Authenticated user's ID
 */
async function logout(refreshTokenValue, userId) {
  if (refreshTokenValue) {
    const tokenHash = _hashRefreshToken(refreshTokenValue);
    await RefreshToken.updateOne(
      { tokenHash, isRevoked: false },
      { $set: { isRevoked: true, revokedAt: new Date() } },
    );
  }
  await _audit(AUDIT_ACTIONS.AUTH_LOGOUT, { actor: userId, resourceId: userId });
}

/**
 * Logout all sessions: revoke ALL refresh tokens for a user.
 *
 * @param {string} userId - User's MongoDB ObjectId string
 */
async function logoutAll(userId) {
  await RefreshToken.updateMany(
    { userId, isRevoked: false },
    { $set: { isRevoked: true, revokedAt: new Date() } },
  );
  await _audit(AUDIT_ACTIONS.AUTH_LOGOUT, {
    actor: userId,
    resourceId: userId,
    metadata: { scope: 'all_sessions' },
  });
}

/**
 * Rotate a refresh token: validates old, issues new, same family.
 *
 * @param {string} refreshTokenValue - Raw refresh token from cookie
 * @param {string} ip - Client IP
 * @param {string} userAgent - Client user agent
 * @returns {{ accessToken: string, refreshToken: string }}
 */
async function refreshTokens(refreshTokenValue, ip, userAgent) {
  if (!refreshTokenValue) {
    throw AppError.unauthorized('Refresh token required', ErrorCodes.AUTH_REFRESH_INVALID);
  }

  const tokenHash = _hashRefreshToken(refreshTokenValue);

  // A3: Constant-time path — both "not found" and "revoked" take identical code paths.
  // This eliminates a timing oracle that could distinguish the two states.
  const storedToken = await RefreshToken.findOne({ tokenHash });

  // Unified guard: treat missing and revoked identically up front
  const isNotFound = !storedToken;
  const isRevoked = storedToken?.isRevoked === true;

  if (isRevoked) {
    // Stolen token detected — revoke entire family
    logger.warn('Revoked refresh token reuse detected — revoking entire family', {
      userId: storedToken.userId,
      family: storedToken.family,
    });

    await RefreshToken.updateMany(
      { family: storedToken.family },
      { $set: { isRevoked: true, revokedAt: new Date() } },
    );

    await _audit(AUDIT_ACTIONS.AUTH_LOGIN_FAILED, {
      actor: storedToken.userId.toString(),
      resourceId: storedToken.userId.toString(),
      metadata: { reason: 'refresh_token_reuse', family: storedToken.family },
    });
  }

  // Same error and same timing for both "not found" and "revoked"
  if (isNotFound || isRevoked) {

    throw AppError.unauthorized('Token reuse detected. All sessions revoked.', ErrorCodes.AUTH_REFRESH_INVALID);
  }

  // Check expiry
  if (storedToken.expiresAt < new Date()) {
    storedToken.isRevoked = true;
    storedToken.revokedAt = new Date();
    await storedToken.save();
    throw AppError.unauthorized('Refresh token expired', ErrorCodes.AUTH_REFRESH_EXPIRED);
  }

  // Verify user still active
  const user = await User.findById(storedToken.userId);
  if (!user || !user.isActive) {
    storedToken.isRevoked = true;
    storedToken.revokedAt = new Date();
    await storedToken.save();
    throw AppError.unauthorized('Account is disabled', ErrorCodes.AUTH_ACCOUNT_DISABLED);
  }

  // A1: ATOMIC token rotation — old revoke + new create in one transaction
  const newRefreshValue = _generateRefreshTokenValue();
  const newTokenHash = _hashRefreshToken(newRefreshValue);

  const session = await mongoose.startSession();
  try {
    await session.withTransaction(async () => {
      await RefreshToken.updateOne(
        { _id: storedToken._id },
        { $set: { isRevoked: true, revokedAt: new Date(), replacedByToken: newTokenHash } },
        { session },
      );

      await RefreshToken.create([{
        userId: user._id,
        tokenHash: newTokenHash,
        ip,
        userAgent,
        expiresAt: _getRefreshExpiryDate(),
        family: storedToken.family,
      }], { session });
    });
  } finally {
    await session.endSession();
  }

  const newAccessToken = _generateAccessToken(user);
  return { accessToken: newAccessToken, refreshToken: newRefreshValue };
}

/**
 * Change password with MongoDB transaction for atomicity.
 *
 * ATOMICITY: user.save() + RefreshToken.updateMany() MUST both
 * succeed or both fail. Without a transaction, a crash between
 * step 1 and step 2 would leave sessions valid for old password.
 *
 * @param {string} userId - Authenticated user's ID
 * @param {string} currentPassword - Current password for verification
 * @param {string} newPassword - New password
 */
async function changePassword(userId, currentPassword, newPassword) {
  validateObjectId(userId, 'userId');
  // Explicitly select sensitive fields needed for this operation
  const user = await User.findById(userId).select('+passwordHash +passwordHistory');
  if (!user) throw AppError.notFound('User not found');

  const isValid = await bcrypt.compare(currentPassword, user.passwordHash);
  if (!isValid) {
    throw AppError.unauthorized('Current password is incorrect', ErrorCodes.AUTH_INVALID_CREDENTIALS);
  }

  if (currentPassword === newPassword) {
    throw AppError.badRequest('New password must be different from current password');
  }

  // Check password history
  if (user.passwordHistory && user.passwordHistory.length > 0) {
    for (const oldHash of user.passwordHistory) {
      const isReused = await bcrypt.compare(newPassword, oldHash);
      if (isReused) {
        throw AppError.badRequest(`Cannot reuse any of your last ${AUTH.PASSWORD_HISTORY_SIZE} passwords`);
      }
    }
  }

  const newHash = await bcrypt.hash(newPassword, config.bcrypt.saltRounds);

  // ── ATOMIC TRANSACTION ──
  const session = await mongoose.startSession();
  try {
    await session.withTransaction(async () => {
      user.passwordHash = newHash;
      user.passwordChangedAt = new Date();

      if (!user.passwordHistory) user.passwordHistory = [];
      user.passwordHistory.push(newHash);
      if (user.passwordHistory.length > AUTH.PASSWORD_HISTORY_SIZE) {
        user.passwordHistory = user.passwordHistory.slice(-AUTH.PASSWORD_HISTORY_SIZE);
      }

      await user.save({ session });

      // Revoke ALL sessions (force re-login everywhere)
      await RefreshToken.updateMany(
        { userId: user._id, isRevoked: false },
        { $set: { isRevoked: true, revokedAt: new Date() } },
        { session },
      );
    });
  } finally {
    await session.endSession();
  }

  await _audit(AUDIT_ACTIONS.AUTH_PASSWORD_CHANGED, {
    actor: userId,
    resourceId: userId,
    metadata: { allSessionsRevoked: true },
  });

  logger.info('Password changed', { userId });
}

/**
 * Get user profile.
 *
 * @param {string} userId
 * @returns {object} Safe user data
 */
async function getProfile(userId) {
  validateObjectId(userId, 'userId');
  const user = await User.findById(userId); // sensitive fields excluded by select:false
  if (!user) throw AppError.notFound('User not found');
  return user.toSafeJSON();
}

/**
 * Setup 2FA: generate TOTP secret.
 *
 * @param {string} userId
 * @returns {{ secret: string, otpAuthUrl: string }}
 */
async function setup2FA(userId) {
  validateObjectId(userId, 'userId');
  const user = await User.findById(userId);
  if (!user) throw AppError.notFound('User not found');

  if (user.twoFactorEnabled) {
    throw AppError.conflict('2FA is already enabled', ErrorCodes.AUTH_2FA_ALREADY_ENABLED);
  }

  // A7: Generate secret but do NOT store in DB yet.
  // Secret is only persisted after successful verify2FA().
  // Return it for the client to scan the QR code.
  const secret = authenticator.generateSecret();
  const otpAuthUrl = authenticator.keyuri(user.email, 'XCoinGateway', secret);

  // Store as pending (encrypted) in a temp field — cleared if never verified
  // In production: use Redis with TTL instead. For MVP: store as pending secret.
  user.twoFactorSecret = encrypt(secret);
  user.twoFactorEnabled = false; // Not enabled until verify2FA() succeeds
  await user.save();

  // Return the RAW secret for QR scanning (one-time only)
  return { secret, otpAuthUrl };
}

/**
 * Verify 2FA code and enable.
 *
 * @param {string} userId
 * @param {string} totpCode
 */
async function verify2FA(userId, totpCode) {
  validateObjectId(userId, 'userId');
  // Explicitly select twoFactorSecret for TOTP validation
  const user = await User.findById(userId).select('+twoFactorSecret');
  if (!user) throw AppError.notFound('User not found');

  if (user.twoFactorEnabled) {
    throw AppError.conflict('2FA is already enabled', ErrorCodes.AUTH_2FA_ALREADY_ENABLED);
  }

  if (!user.twoFactorSecret) {
    throw AppError.badRequest('2FA setup not initiated. Call POST /2fa/setup first.');
  }

  const isValid = await _validateTOTP(user._id, totpCode, user.twoFactorSecret);
  if (!isValid) {
    throw AppError.unauthorized('Invalid or already used 2FA code', ErrorCodes.AUTH_2FA_INVALID);
  }

  // Only NOW mark 2FA as enabled
  user.twoFactorEnabled = true;
  await user.save();

  await _audit(AUDIT_ACTIONS.AUTH_2FA_ENABLED, { actor: userId, resourceId: userId });
  logger.info('2FA enabled', { userId });
}

/**
 * Disable 2FA after verifying current code.
 *
 * @param {string} userId
 * @param {string} totpCode
 */
async function disable2FA(userId, totpCode) {
  validateObjectId(userId, 'userId');
  const user = await User.findById(userId).select('+twoFactorSecret');
  if (!user) throw AppError.notFound('User not found');

  if (!user.twoFactorEnabled) {
    throw AppError.badRequest('2FA is not enabled');
  }

  const isValid = await _validateTOTP(user._id, totpCode, user.twoFactorSecret);
  if (!isValid) {
    throw AppError.unauthorized('Invalid or already used 2FA code', ErrorCodes.AUTH_2FA_INVALID);
  }

  user.twoFactorEnabled = false;
  user.twoFactorSecret = null;
  await user.save();

  await _audit(AUDIT_ACTIONS.AUTH_2FA_DISABLED, { actor: userId, resourceId: userId });
  logger.info('2FA disabled', { userId });
}

module.exports = {
  register,
  login,
  logout,
  logoutAll,
  refreshTokens,
  changePassword,
  getProfile,
  setup2FA,
  verify2FA,
  disable2FA,
};
