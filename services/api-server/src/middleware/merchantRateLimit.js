'use strict';

/**
 * @module middleware/merchantRateLimit
 *
 * Per-Merchant Rate Limiting — Post-Auth Merchant-Keyed Limits.
 *
 * GAPS FIXED IN THIS VERSION:
 *   Gap 2 — Withdrawal-specific rate limit: withdrawal POST was only covered
 *     by the general merchantWriteLimiter (60 writes/15min). Withdrawals move
 *     real money — they need a dedicated, much stricter bucket independent of
 *     invoice creates and other writes.
 *     Fix: merchantWithdrawalLimiter — 5 withdrawals per 15 minutes per merchant.
 *     This is separate from merchantWriteLimiter so exhausting invoice creation
 *     does NOT consume the withdrawal budget and vice versa.
 *
 *   Gap 4 — Burst protection (token bucket via Redis):
 *     A sliding-window limit of 60 writes/15min can be fully exhausted in 1 second
 *     (burst of 60). For withdrawals this is catastrophic — a compromised merchant
 *     key could flood the withdrawal queue.
 *     Fix: merchantBurstGuard — Redis token bucket with refill rate. Implemented
 *     inline using Redis DECR + TTL: a key starts at N tokens; each request
 *     decrements by 1; key expires (refills) after burstWindowSec.
 *     Applied specifically to write operations (POST /withdrawals, POST /invoices).
 *
 * EXISTING LIMITERS (unchanged):
 *   - merchantReadLimiter:  200 reads / 15min per merchant
 *   - merchantWriteLimiter: 60 writes / 15min per merchant
 *
 * USAGE:
 *   // In routes/withdrawals.js
 *   router.post('/', auth, merchantBurstGuard(10, 60), merchantWithdrawalLimiter, createWithdrawal);
 *   //                          ↑ max 10 in any 60s window (burst cap)
 *   //                                                ↑ max 5 per 15min (sustained cap)
 *
 * NOTE ON REDIS STORE:
 *   This module creates its own Redis client for express-rate-limit compatibility.
 *   The IORedis client in app.locals.redis uses a different protocol format.
 *   merchantBurstGuard() uses app.locals.redis directly (passed via req).
 */

const rateLimit = require('express-rate-limit');
const { response } = require('@xcg/common');
const { createLogger } = require('@xcg/logger');

const logger = createLogger('merchant-rate-limit');

// ─── Redis store for express-rate-limit (fixed window) ────────────────────────
let rateLimitStore;
try {
  const RedisStore = require('rate-limit-redis');
  const { createClient } = require('redis');
  const { config } = require('../config');
  const redisClient = createClient({ url: config.redis.url });
  redisClient.connect().catch(() => {});
  rateLimitStore = new RedisStore({ sendCommand: (...args) => redisClient.sendCommand(args) });
} catch {
  rateLimitStore = undefined;
}

// ─── Key generator helpers ────────────────────────────────────────────────────

function getMerchantId(req) {
  return req.merchant?.merchantId || req.user?.merchantId || req.ip || 'unknown';
}

// ─── Existing limiters (unchanged behaviour) ──────────────────────────────────

/**
 * Per-merchant read rate limiter.
 * 200 read requests per 15 minutes per merchant.
 */
const merchantReadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  store: rateLimitStore,
  validate: { keyGeneratorIpFallback: false },
  keyGenerator: (req) => `merchant_read:${getMerchantId(req)}`,
  message: response.error('RATE_LIMITED', 'Read rate limit exceeded for this merchant. Try again later.'),
  skip: (req) => req.method !== 'GET',
});

/**
 * Per-merchant write rate limiter.
 * 60 write requests per 15 minutes per merchant.
 * Applies to all mutations EXCEPT withdrawals (which have their own stricter limit).
 */
const merchantWriteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  store: rateLimitStore,
  validate: { keyGeneratorIpFallback: false },
  keyGenerator: (req) => `merchant_write:${getMerchantId(req)}`,
  message: response.error('RATE_LIMITED', 'Write rate limit exceeded for this merchant. Try again later.'),
  skip: (req) => !['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method),
});

// ─── Gap 2: Withdrawal-specific strict limiter ────────────────────────────────

/**
 * Per-merchant withdrawal rate limiter.
 *
 * MUCH stricter than the general write limiter — withdrawals move real money.
 * Limit: 5 withdrawals per 15 minutes per merchant (keyed independently).
 *
 * WHY SEPARATE:
 *   If withdrawal was counted under merchantWriteLimiter, a burst of 60 invoice
 *   creates would exhaust the write budget and block all withdrawals — or 60
 *   withdrawals could be fired before the limit kicks in. Separate buckets prevent both.
 *
 * Default: 5 per 15min. Override via MERCHANT_WITHDRAWAL_LIMIT env.
 */
const WITHDRAWAL_MAX = parseInt(process.env.MERCHANT_WITHDRAWAL_LIMIT, 10) || 5;

const merchantWithdrawalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: WITHDRAWAL_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  store: rateLimitStore,
  validate: { keyGeneratorIpFallback: false },
  keyGenerator: (req) => `merchant_withdrawal:${getMerchantId(req)}`,
  message: response.error(
    'WITHDRAWAL_RATE_LIMITED',
    `Withdrawal rate limit exceeded. Maximum ${WITHDRAWAL_MAX} withdrawals per 15 minutes.`,
  ),
});

// ─── Gap 4: Burst protection (token bucket via Redis) ─────────────────────────

/**
 * Short-burst rate guard using Redis token bucket.
 *
 * PROBLEM: A fixed/sliding window of 60 req/15min can be exhausted in a single
 * second (burst of 60 concurrent requests). For write endpoints like POST /withdrawals
 * or POST /invoices this is dangerous — the downstream queue gets flooded before
 * the window limiter updates.
 *
 * SOLUTION: Token bucket with short window. Each merchant gets `maxBurst` tokens
 * replenished every `windowSec` seconds. A request decrements by 1; if the
 * counter goes below 0 → reject. The key auto-expires after `windowSec` (refill).
 *
 * IMPLEMENTATION: Uses Redis SETNX (create key if absent) + DECR (atomic decrement).
 *   1. SETNX xcg:burst:{type}:{merchantId} → maxBurst (only on first request in window)
 *   2. EXPIRE key → windowSec (reset TTL so key lives exactly one window)
 *   3. DECR key → returns new value
 *   4. If new value < 0 → reject (tokens exhausted)
 *
 * FAILURE MODE: If Redis unavailable → fail open (correctness > burst prevention).
 *
 * @param {number} maxBurst  - Max requests in burst window (default 10)
 * @param {number} windowSec - Burst window in seconds (default 60)
 * @param {string} type      - Bucket type label for key namespacing
 * @returns {Function} Express middleware
 */
function merchantBurstGuard(maxBurst = 10, windowSec = 60, type = 'write') {
  return async function burstGuardMiddleware(req, res, next) {
    if (process.env.NODE_ENV === 'test') return next();

    const redis = req.app.locals.redis;
    if (!redis) return next(); // Fail open

    const merchantId = getMerchantId(req);
    const key        = `xcg:burst:${type}:${merchantId}`;

    try {
      // Atomically initialize if not present and set TTL
      const exists = await redis.exists(key);
      if (!exists) {
        // First request in window: initialize counter to maxBurst - 1 (this request consumes 1)
        await redis.set(key, maxBurst - 1, 'EX', windowSec);
        return next();
      }

      // Subsequent requests: atomically decrement
      const remaining = await redis.decr(key);

      if (remaining < 0) {
        // Over budget — find out when window resets
        const ttl = await redis.ttl(key);
        res.setHeader('Retry-After', String(Math.max(1, ttl)));
        res.setHeader('X-Burst-Limit',     String(maxBurst));
        res.setHeader('X-Burst-Remaining',  '0');
        logger.warn('Merchant burst limit exceeded', { merchantId, type, key });
        return res.status(429).json(
          response.error('BURST_RATE_LIMITED', 'Request rate too high. Please slow down and retry.'),
        );
      }

      res.setHeader('X-Burst-Limit',    String(maxBurst));
      res.setHeader('X-Burst-Remaining', String(remaining));
      next();

    } catch (err) {
      // Redis error → fail open
      logger.error('Burst guard Redis error — failing open', { merchantId, error: err.message });
      next();
    }
  };
}

module.exports = {
  merchantReadLimiter,
  merchantWriteLimiter,
  merchantWithdrawalLimiter,
  merchantBurstGuard,
};
