'use strict';

/**
 * @module middleware/ipRateLimit
 *
 * PRE-AUTH IP-LEVEL RATE LIMITING (Gap 1 fix).
 *
 * WHY THIS MATTERS:
 *   Per-merchant rate limiting (merchantRateLimit.js) applies AFTER HMAC auth —
 *   meaning the nonce check, Redis lookup, and merchant DB lookup all execute
 *   BEFORE rate limiting kicks in. A brute-force attacker cycling nonces can
 *   hammer those lookup paths without ever hitting a merchant-level limit.
 *
 * THIS middleware runs BEFORE any auth, keyed by raw IP. It provides a
 * cheap, early gate that blocks volumetric attacks at the edge of the app,
 * before any business logic executes.
 *
 * DESIGN:
 *   - Implemented via IORedis (NOT express-rate-limit) so we can use the
 *     existing IORedis instance (app.locals.redis) already wired everywhere.
 *     This avoids a second Redis connection just for rate limiting.
 *   - Sliding window: uses Redis ZADD/ZRANGEBYSCORE pattern for accuracy
 *     (vs fixed-window which allows 2x burst at window boundaries).
 *   - Separate limits per route class (auth, merchant-api, general).
 *   - Fails OPEN if Redis is unavailable (payment system availability > brute force risk).
 *
 * LIMITS (tunable via ENV):
 *   IP_LIMIT_AUTH_WINDOW_SEC    — Window seconds for auth endpoints (default 300 = 5 min)
 *   IP_LIMIT_AUTH_MAX           — Max auth requests per IP per window (default 20)
 *   IP_LIMIT_MERCHANT_WINDOW_SEC — Window for merchant API endpoints (default 60 = 1 min)
 *   IP_LIMIT_MERCHANT_MAX       — Max merchant API requests per IP per window (default 120)
 *   IP_LIMIT_GENERAL_WINDOW_SEC — Window for all other /api/ routes (default 60)
 *   IP_LIMIT_GENERAL_MAX        — Max general requests per IP per window (default 300)
 *
 * USAGE in app.js (BEFORE all other middleware except Helmet/CORS):
 *   const { ipAuthLimiter, ipMerchantLimiter, ipGeneralLimiter } = require('./middleware/ipRateLimit');
 *   app.use('/api/v1/auth',         ipAuthLimiter);
 *   app.use('/api/v1/payments',     ipMerchantLimiter);
 *   app.use('/api/v1/withdrawals',  ipMerchantLimiter);
 *   app.use('/api/',                ipGeneralLimiter);
 */

const { createLogger } = require('@xcg/logger');
const { response }     = require('@xcg/common');

const logger = createLogger('ip-rate-limit');

// ─── Config (from ENV with safe defaults) ─────────────────────────────────────
const CFG = {
  auth: {
    windowSec: parseInt(process.env.IP_LIMIT_AUTH_WINDOW_SEC, 10)    || 300,  // 5 min
    max:       parseInt(process.env.IP_LIMIT_AUTH_MAX, 10)            || 20,   // 20 auth attempts per IP / 5 min
  },
  merchant: {
    windowSec: parseInt(process.env.IP_LIMIT_MERCHANT_WINDOW_SEC, 10) || 60,   // 1 min
    max:       parseInt(process.env.IP_LIMIT_MERCHANT_MAX, 10)        || 120,  // ~2 req/sec per IP
  },
  general: {
    windowSec: parseInt(process.env.IP_LIMIT_GENERAL_WINDOW_SEC, 10)  || 60,   // 1 min
    max:       parseInt(process.env.IP_LIMIT_GENERAL_MAX, 10)         || 300,  // ~5 req/sec per IP
  },
};

// ─── Sliding window check via Redis ───────────────────────────────────────────

/**
 * Sliding window rate limit check using sorted set (ZADD / ZREMRANGEBYSCORE / ZCARD).
 *
 * Algorithm:
 *   1. Remove entries older than now - windowSec
 *   2. Count remaining entries
 *   3. If count >= max → reject
 *   4. Else add current timestamp → allow
 *
 * Keys: xcg:iplimit:{type}:{ip}
 *
 * @param {object} redis       - IORedis client
 * @param {string} type        - Limiter type (auth|merchant|general)
 * @param {string} ip          - Client IP
 * @param {number} windowSec   - Window in seconds
 * @param {number} max         - Max requests in window
 * @returns {Promise<{allowed: boolean, remaining: number, retryAfterSec: number}>}
 */
async function checkSlidingWindow(redis, type, ip, windowSec, max) {
  const now     = Date.now();
  const windowMs = windowSec * 1000;
  const cutoff  = now - windowMs;
  const key     = `xcg:iplimit:${type}:${ip}`;

  try {
    const pipeline = redis.pipeline();
    // Remove expired entries
    pipeline.zremrangebyscore(key, '-inf', cutoff);
    // Count current window
    pipeline.zcard(key);
    // Set TTL so key auto-expires (prevents memory leak for inactive IPs)
    pipeline.expire(key, windowSec + 10);

    const results = await pipeline.exec();
    const count   = results[1][1]; // [err, value] pairs

    if (count >= max) {
      // Oldest entry tells us when the window opens up
      const oldest = await redis.zrange(key, 0, 0, 'WITHSCORES');
      const oldestTs = oldest.length >= 2 ? parseInt(oldest[1], 10) : now;
      const retryAfterSec = Math.ceil((oldestTs + windowMs - now) / 1000);
      return { allowed: false, remaining: 0, retryAfterSec: Math.max(1, retryAfterSec) };
    }

    // Add this request with score = timestamp (unique member = ts:random)
    await redis.zadd(key, now, `${now}:${Math.random().toString(36).slice(2)}`);
    return { allowed: true, remaining: max - count - 1, retryAfterSec: 0 };

  } catch (err) {
    // Redis failure → fail open (availability over brute-force protection)
    logger.error('IP rate limit Redis error — failing open', { type, ip, error: err.message });
    return { allowed: true, remaining: max, retryAfterSec: 0 };
  }
}

// ─── Middleware factory ────────────────────────────────────────────────────────

/**
 * Build an IP-level rate limit middleware for a given class.
 *
 * @param {string} type      - 'auth' | 'merchant' | 'general'
 * @param {number} windowSec
 * @param {number} max
 */
function buildIpLimiter(type, windowSec, max) {
  return async function ipRateLimitMiddleware(req, res, next) {
    // Skip in test environment to avoid polluting test Redis / failing CI
    if (process.env.NODE_ENV === 'test') return next();

    const redis = req.app.locals.redis;
    if (!redis) return next(); // Redis not ready — fail open

    const ip = req.ip || req.connection?.remoteAddress || 'unknown';

    const { allowed, remaining, retryAfterSec } = await checkSlidingWindow(
      redis, type, ip, windowSec, max,
    );

    // Always set informational headers (RFC 6585)
    res.setHeader('X-RateLimit-Limit',     String(max));
    res.setHeader('X-RateLimit-Remaining', String(Math.max(0, remaining)));
    res.setHeader('X-RateLimit-Window',    `${windowSec}s`);

    if (!allowed) {
      res.setHeader('Retry-After', String(retryAfterSec));
      logger.warn('IP rate limit exceeded', { type, ip, retryAfterSec });
      return res.status(429).json(
        response.error('IP_RATE_LIMITED', 'Too many requests from this IP. Please slow down.'),
      );
    }

    next();
  };
}

// ─── Exported limiters ────────────────────────────────────────────────────────

/** Pre-auth IP limiter for /api/v1/auth — strictest */
const ipAuthLimiter     = buildIpLimiter('auth',     CFG.auth.windowSec,     CFG.auth.max);

/** Pre-auth IP limiter for /api/v1/payments, /api/v1/withdrawals */
const ipMerchantLimiter = buildIpLimiter('merchant', CFG.merchant.windowSec, CFG.merchant.max);

/** General IP limiter for all /api/ routes */
const ipGeneralLimiter  = buildIpLimiter('general',  CFG.general.windowSec,  CFG.general.max);

module.exports = { ipAuthLimiter, ipMerchantLimiter, ipGeneralLimiter, buildIpLimiter };
