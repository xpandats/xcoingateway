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

    // 2. Verify token (algorithm pinned to HS256 — prevents algorithm confusion attacks)
    let decoded;
    try {
      decoded = jwt.verify(token, config.jwt.accessSecret, { algorithms: ['HS256'] });
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
    req.user = {
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
      merchantId: user.merchantId?.toString() || null,
    };

    // 6. Propagate auth context through AsyncLocalStorage
    // After this, getRequestContext() anywhere in the chain includes the user.
    updateRequestContext({
      userId: user._id.toString(),
      role: user.role,
    });

    next();
  } catch (err) {
    next(err);
  }
}

module.exports = { authenticate };
