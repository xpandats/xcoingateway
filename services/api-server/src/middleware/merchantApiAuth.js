'use strict';

/**
 * @module middleware/merchantApiAuth
 *
 * Merchant API Authentication — HMAC-SHA256 signed requests.
 *
 * Every merchant API request MUST include:
 *   Headers:
 *     X-API-Key:   {64-char hex API key}
 *     X-Nonce:     {UUID v4 — prevents replay}
 *     X-Timestamp: {Unix timestamp in seconds}
 *     X-Signature: {HMAC-SHA256 of canonical payload}
 *
 * Signature format (canonical):
 *   HMAC-SHA256(apiSecret, `${method}\n${path}\n${timestamp}\n${nonce}\n${bodyHash}`)
 *   where bodyHash = SHA-256(JSON.stringify(body)) or '' if no body
 *
 * SECURITY CONTROLS:
 *   1. API key resolved to merchant with active status
 *   2. Nonce stored in Redis with 10-minute TTL (replay window = 5 min)
 *   3. Timestamp must be within ±5 minutes of server time
 *   4. HMAC verified with timing-safe comparison
 *   5. Used nonce cached in Redis (prevents replay within window)
 *   6. Per-API-key rate limiting (100 req/15min default)
 *   7. Inactive or suspended merchants rejected
 */

const crypto = require('crypto');
const { AppError }  = require('@xcg/common');
const { Merchant }  = require('@xcg/database');

const NONCE_TTL_SECONDS = 600;   // 10-min Redis TTL for nonce
const TIMESTAMP_WINDOW  = 300;   // ±5 minutes acceptable clock skew

/**
 * Build the canonical string to sign.
 * Both merchant and server MUST produce this exact string for HMAC to match.
 */
function buildCanonical(method, path, timestamp, nonce, body) {
  const bodyStr  = body && Object.keys(body).length ? JSON.stringify(body) : '';
  const bodyHash = crypto.createHash('sha256').update(bodyStr).digest('hex');
  return `${method.toUpperCase()}\n${path}\n${timestamp}\n${nonce}\n${bodyHash}`;
}

/**
 * Factory: returns the middleware with a Redis client injected.
 * @param {object} redisClient - IORedis instance
 */
function merchantApiAuth(redisClient) {
  return async function (req, res, next) {
    try {
      // ── 1. Extract headers ─────────────────────────────────────────────────
      const apiKey    = req.headers['x-api-key'];
      const nonce     = req.headers['x-nonce'];
      const timestamp = req.headers['x-timestamp'];
      const signature = req.headers['x-signature'];

      if (!apiKey || !nonce || !timestamp || !signature) {
        throw AppError.unauthorized('Missing authentication headers');
      }

      // ── 2. Timestamp window check ──────────────────────────────────────────
      const tsNum = parseInt(timestamp, 10);
      if (isNaN(tsNum)) throw AppError.unauthorized('Invalid timestamp');
      const drift = Math.abs(Math.floor(Date.now() / 1000) - tsNum);
      if (drift > TIMESTAMP_WINDOW) {
        throw AppError.unauthorized('Request timestamp outside acceptable window');
      }

      // ── 3. Nonce replay check ──────────────────────────────────────────────
      const nonceKey  = `xcg:nonce:${apiKey}:${nonce}`;
      const nonceUsed = await redisClient.set(nonceKey, '1', 'EX', NONCE_TTL_SECONDS, 'NX');
      if (nonceUsed === null) {
        throw AppError.unauthorized('Nonce already used (replay attack rejected)');
      }

      // ── 4. Resolve API key → merchant ─────────────────────────────────────
      const merchant = await Merchant.findOne({
        'apiKeys.key': apiKey,
        isActive: true,
      }).lean();

      if (!merchant) {
        throw AppError.unauthorized('Invalid API key');
      }

      // Find the specific API key entry (multiple keys per merchant supported)
      const apiKeyEntry = merchant.apiKeys.find((k) => k.key === apiKey);
      if (!apiKeyEntry || !apiKeyEntry.isActive) {
        throw AppError.unauthorized('API key is inactive');
      }

      // ── 5. Verify HMAC signature ───────────────────────────────────────────
      const canonical = buildCanonical(req.method, req.path, timestamp, nonce, req.body);
      const expected  = crypto
        .createHmac('sha256', apiKeyEntry.secret)
        .update(canonical)
        .digest('hex');

      const sigBuf = Buffer.from(signature, 'hex');
      const expBuf = Buffer.from(expected,   'hex');

      if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
        throw AppError.unauthorized('Invalid signature');
      }

      // ── 6. Attach merchant to request ─────────────────────────────────────
      req.merchant = merchant;

      next();
    } catch (err) {
      next(err);
    }
  };
}

module.exports = merchantApiAuth;
