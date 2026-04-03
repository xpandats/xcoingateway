'use strict';

/**
 * @module middleware/merchantRateLimit
 *
 * C3: Per-Merchant Read Rate Limiting.
 *
 * WHY: The general IP-based rate limiter (100 req/15min) allows a merchant
 * to call GET /invoices?limit=100 repeatedly and bulk-extract all their data —
 * 100 requests × 100 records = 10,000 records in one window.
 *
 * This middleware adds a secondary rate limit keyed by merchantId,
 * applied AFTER merchantAuth/authenticate middleware (so merchantId is known).
 *
 * Limits are separate per feature (reads vs writes) and configurable via ENV.
 */

const rateLimit = require('express-rate-limit');
const { response } = require('@xcg/common');

// C3: Attempt Redis store (same approach as global limiter)
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

/**
 * Per-merchant read rate limiter.
 * Keyed by merchantId (from JWT or HMAC auth).
 * Limit: 200 read requests per 15 minutes per merchant.
 */
const merchantReadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,                  // 200 reads per merchant per window
  standardHeaders: true,
  legacyHeaders: false,
  store: rateLimitStore,
  keyGenerator: (req) => {
    // Key by merchantId — not by IP (merchants may share IPs via CDN/proxy)
    const merchantId = req.merchant?.merchantId || req.user?.merchantId || req.ip;
    return `merchant_read:${merchantId}`;
  },
  message: response.error('RATE_LIMITED', 'Read rate limit exceeded for this merchant. Try again later.'),
  skip: (req) => {
    // Only apply to GET requests
    return req.method !== 'GET';
  },
});

/**
 * Per-merchant write rate limiter.
 * Keyed by merchantId.
 * Limit: 60 write requests per 15 minutes per merchant.
 */
const merchantWriteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 60,                   // 60 writes per merchant per window
  standardHeaders: true,
  legacyHeaders: false,
  store: rateLimitStore,
  keyGenerator: (req) => {
    const merchantId = req.merchant?.merchantId || req.user?.merchantId || req.ip;
    return `merchant_write:${merchantId}`;
  },
  message: response.error('RATE_LIMITED', 'Write rate limit exceeded for this merchant. Try again later.'),
  skip: (req) => {
    // Only apply to mutation requests
    return !['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method);
  },
});

module.exports = { merchantReadLimiter, merchantWriteLimiter };
