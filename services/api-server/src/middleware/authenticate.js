'use strict';

/**
 * @module middleware/authenticate
 *
 * JWT Authentication Middleware — Bank-Grade.
 *
 * Flow:
 *   1. Extract Bearer token from Authorization header
 *   2. Verify signature with algorithm pinning (HS256 only)
 *   3. Check jti blocklist in Redis (emergency revocation support)
 *   4. Verify user exists and is active in DB
 *   5. Check if password changed after token was issued
 *   6. Attach user to req.user
 *   7. Update AsyncLocalStorage context with userId + role
 *
 * JTI BLOCKLIST (Gap A fix):
 *   Every access token now contains a `jti` (JWT ID — 16-byte random hex) claim.
 *   The blocklist check happens BEFORE the DB lookup:
 *     key: xcg:jti:blocked:{jti}
 *     value: '1'
 *     TTL: token's remaining lifetime (so blocklist entries auto-expire with the token)
 *
 *   To revoke a specific token immediately (compromised admin, stolen device):
 *     await redis.set(`xcg:jti:blocked:${jti}`, '1', 'EX', remainingTtl)
 *   This is called by the admin emergency revocation endpoint.
 *
 *   FAILURE MODE: If Redis is unavailable, the blocklist check is SKIPPED (fail-open).
 *   This is an intentional trade-off — blocking ALL authenticated traffic because Redis
 *   is down is worse than a brief blocklist bypass. Admin should be alerted immediately.
 *   For maximum security, change fail-open to fail-closed by returning 503 on Redis failure.
 */

const jwt    = require('jsonwebtoken');
const crypto = require('crypto');
const { User } = require('@xcg/database');
const { AppError, ErrorCodes, updateRequestContext } = require('@xcg/common');
const { config } = require('../config');
const { createLogger } = require('@xcg/logger');

const logger = createLogger('authenticate');

const JTI_BLOCKLIST_PREFIX = 'xcg:jti:blocked:';

/**
 * Check whether a jti has been explicitly revoked.
 *
 * @param {object|null} redis - IORedis client from app.locals.redis
 * @param {string} jti        - JWT ID claim from the token
 * @param {number} exp        - JWT exp claim (Unix seconds)
 * @returns {Promise<boolean>} true if blocked
 */
async function isJtiBlocked(redis, jti, exp) {
  if (!redis || !jti) return false;
  try {
    const blocked = await redis.get(`${JTI_BLOCKLIST_PREFIX}${jti}`);
    return blocked === '1';
  } catch (err) {
    // Redis unavailable — fail-open (log loudly)
    logger.error('JTI blocklist check failed — Redis unavailable (fail-open)', {
      error: err.message,
      jti,
    });
    return false; // Fail-open: don't block all traffic because Redis is down
  }
}

/**
 * Revoke a specific JWT by its jti, expiring automatically when the token would have.
 * Called by admin emergency token revocation endpoint.
 *
 * @param {object} redis - IORedis client
 * @param {string} jti   - JWT ID claim
 * @param {number} exp   - JWT exp claim (Unix seconds) — used to calculate TTL
 */
async function revokeJti(redis, jti, exp) {
  if (!redis || !jti) return;
  const now = Math.floor(Date.now() / 1000);
  const remainingTtl = Math.max(exp - now, 0);
  if (remainingTtl === 0) return; // Already expired — no need to blocklist

  await redis.set(`${JTI_BLOCKLIST_PREFIX}${jti}`, '1', 'EX', remainingTtl);
  logger.info('JTI revoked — token blocklisted until expiry', {
    jti,
    remainingTtlSeconds: remainingTtl,
  });
}

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

    // 3. JTI blocklist check (Gap A fix — emergency revocation)
    // Checks Redis for this specific token's jti BEFORE the DB lookup.
    // If the jti is blocklisted, the token is rejected regardless of signature validity.
    // This allows immediate revocation of a specific token without revoking all user sessions.
    const redis = req.app?.locals?.redis || null;
    if (decoded.jti) {
      const blocked = await isJtiBlocked(redis, decoded.jti, decoded.exp);
      if (blocked) {
        logger.warn('JTI blocklisted — token explicitly revoked', {
          userId: decoded.userId,
          jti: decoded.jti,
          requestId: req.requestId,
          ip: req.ip,
        });
        throw AppError.unauthorized('Token has been revoked. Please log in again.', ErrorCodes.AUTH_TOKEN_INVALID);
      }
    }

    // 4. Verify user exists and is active
    // Note: not selecting sensitive fields, but we need passwordChangedAt for step 5
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

    // 5. Rotation detection: was password changed after this token was issued?
    // If yes, the old token must be rejected even though the signature is valid.
    if (user.passwordChangedAt) {
      const changedTimestamp = Math.floor(user.passwordChangedAt.getTime() / 1000);
      if (decoded.iat < changedTimestamp) {
        throw AppError.unauthorized('Password changed. Please log in again.', ErrorCodes.AUTH_TOKEN_INVALID);
      }
    }

    // 6. Attach user to request
    // G3: Use DB role (not decoded.role) — prevents privilege persistence
    // after an admin changes the user's role mid-session.
    req.user = {
      userId:     user._id.toString(),
      email:      user.email,
      role:       user.role,          // From DB — always fresh
      merchantId: user.merchantId?.toString() || null,
      jti:        decoded.jti || null, // Expose jti for downstream emergency revocation
    };

    // 7. Propagate auth context through AsyncLocalStorage
    // After this, getRequestContext() anywhere in the chain includes the user.
    updateRequestContext({
      userId: user._id.toString(),
      role:   user.role,
    });

    // T-1: Warn on IP prefix mismatch — possible stolen token from different network.
    // Non-blocking: don't reject (CGNAT, VPN, mobile users have dynamic IPs).
    if (decoded.iph) {
      const currentPrefix = req.ip ? req.ip.split('.').slice(0, 3).join('.') : '';
      const currentHash   = crypto.createHash('sha256').update(currentPrefix).digest('hex').slice(0, 8);
      if (decoded.iph !== currentHash) {
        logger.warn('T-1: JWT IP prefix mismatch — possible stolen token', {
          requestId: req.requestId,
          userId:    user._id.toString(),
        });
      }
    }

    next();
  } catch (err) {
    next(err);
  }
}

module.exports = { authenticate, revokeJti };
