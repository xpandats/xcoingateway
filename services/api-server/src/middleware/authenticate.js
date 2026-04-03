'use strict';

/**
 * @module middleware/authenticate
 *
 * JWT Authentication Middleware — Bank-Grade.
 *
 * Flow:
 *   1. Extract Bearer token from Authorization header
 *   2. Verify signature with algorithm pinning (HS256 only)
 *   3. Verify user exists and is active in DB
 *   4. Check if password changed after token was issued
 *   5. Attach user to req.user
 *   6. Update AsyncLocalStorage context with userId + role
 */

const jwt = require('jsonwebtoken');
const { User } = require('@xcg/database');
const { AppError, ErrorCodes, updateRequestContext } = require('@xcg/common');
const { config } = require('../config');
const { createLogger } = require('@xcg/logger');

const logger = createLogger('authenticate');

/**
 * Authentication middleware.
 * Requires valid JWT access token in Authorization: Bearer <token>.
 */
async function authenticate(req, res, next) {
  try {
    // 1. Extract token
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw AppError.unauthorized('Access token required', ErrorCodes.AUTH_TOKEN_MISSING);
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      throw AppError.unauthorized('Access token required', ErrorCodes.AUTH_TOKEN_MISSING);
    }

    // 2. Verify token
    // T-3: Pin to HS256 ONLY. Explicitly rejects 'none', RS256, and any other algorithm.
    // Even with a secret provided, explicit pinning is required as defence-in-depth
    // against JWT library bugs or future algorithm downgrade attacks.
    let decoded;
    try {
      decoded = jwt.verify(token, config.jwt.accessSecret, {
        algorithms: ['HS256'], // ONLY HS256 accepted
      });
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        throw AppError.unauthorized('Access token expired', ErrorCodes.AUTH_TOKEN_EXPIRED);
      }
      throw AppError.unauthorized('Invalid access token', ErrorCodes.AUTH_TOKEN_INVALID);
    }

    // 3. Verify user exists and is active
    // Note: Not selecting sensitive fields, but we need passwordChangedAt for step 4
    const user = await User.findById(decoded.userId).select(
      'email role merchantId isActive lockUntil passwordChangedAt',
    );

    if (!user) {
      throw AppError.unauthorized('User not found', ErrorCodes.AUTH_TOKEN_INVALID);
    }
    if (!user.isActive) {
      throw AppError.unauthorized('Account is disabled', ErrorCodes.AUTH_ACCOUNT_DISABLED);
    }
    if (user.isLocked) {
      throw AppError.unauthorized('Account is locked', ErrorCodes.AUTH_ACCOUNT_LOCKED);
    }

    // 4. Rotation detection: was password changed after this token was issued?
    // If yes, the old token must be rejected even though the signature is valid.
    if (user.passwordChangedAt) {
      const changedTimestamp = Math.floor(user.passwordChangedAt.getTime() / 1000);
      if (decoded.iat < changedTimestamp) {
        throw AppError.unauthorized('Password changed. Please log in again.', ErrorCodes.AUTH_TOKEN_INVALID);
      }
    }

    // 5. Attach user to request
    // G3: Use DB role (not decoded.role) — prevents privilege persistence
    // after an admin changes the user's role mid-session.
    req.user = {
      userId: user._id.toString(),
      email: user.email,
      role: user.role,          // From DB — always fresh
      merchantId: user.merchantId?.toString() || null,
    };

    // 6. Propagate auth context through AsyncLocalStorage
    // After this, getRequestContext() anywhere in the chain includes the user.
    updateRequestContext({
      userId: user._id.toString(),
      role: user.role,
    });

    // T-1: Warn on IP prefix mismatch — possible stolen token from different network.
    // Non-blocking: don't reject (CGNAT, VPN, mobile users have dynamic IPs).
    if (decoded.iph) {
      const crypto = require('crypto');
      const currentPrefix = req.ip ? req.ip.split('.').slice(0, 3).join('.') : '';
      const currentHash = crypto.createHash('sha256').update(currentPrefix).digest('hex').slice(0, 8);
      if (decoded.iph !== currentHash) {
        logger.warn('T-1: JWT IP prefix mismatch — possible stolen token', {
          requestId: req.requestId,
          userId: user._id.toString(),
        });
      }
    }

    next();
  } catch (err) {
    next(err);
  }
}

module.exports = { authenticate };
