'use strict';

/**
 * JWT Authentication Middleware.
 *
 * Validates access tokens on protected routes.
 * Attaches decoded user data to req.user.
 *
 * Flow:
 *   1. Extract token from Authorization: Bearer <token>
 *   2. Verify signature + expiry
 *   3. Check if user exists and is active
 *   4. Attach user to request
 */

const jwt = require('jsonwebtoken');
const { User } = require('@xcg/database');
const { AppError, ErrorCodes } = require('@xcg/common');
const { config } = require('../config');

/**
 * Authentication middleware.
 * Requires valid JWT access token in Authorization header.
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
    let decoded;
    try {
      decoded = jwt.verify(token, config.jwt.accessSecret, { algorithms: ['HS256'] });
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        throw AppError.unauthorized('Access token expired', ErrorCodes.AUTH_TOKEN_EXPIRED);
      }
      throw AppError.unauthorized('Invalid access token', ErrorCodes.AUTH_TOKEN_INVALID);
    }

    // 3. Check user exists and is active
    const user = await User.findById(decoded.userId).select('-refreshTokens');
    if (!user) {
      throw AppError.unauthorized('User not found', ErrorCodes.AUTH_TOKEN_INVALID);
    }
    if (!user.isActive) {
      throw AppError.unauthorized('Account is disabled', ErrorCodes.AUTH_ACCOUNT_DISABLED);
    }
    if (user.isLocked) {
      throw AppError.unauthorized('Account is locked', ErrorCodes.AUTH_ACCOUNT_LOCKED);
    }

    // 4. Check if password was changed after token was issued
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

    next();
  } catch (err) {
    next(err);
  }
}

module.exports = { authenticate };
