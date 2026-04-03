'use strict';

/**
 * @module middleware/merchantApiAuth
 *
 * Merchant API Authentication — HMAC-SHA256 signed requests.
 *
 * Every merchant API request MUST include:
 *   Headers:
 *     X-API-Key:   {public keyId}
 *     X-Nonce:     {UUID v4 — single use within 10-min window}
 *     X-Timestamp: {Unix seconds — must be within ±5 min of server time}
 *     X-Signature: {HMAC-SHA256 of canonical string}
 *
 * Canonical string format:
 *   METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY_SHA256
 *
 * Body hash: SHA-256 of JSON.stringify(requestBody) or '' for empty body.
 *
 * SECURITY GUARANTEES:
 *   1. Nonce deduplicated in Redis (10-min TTL) — replay attack prevention
 *   2. Timestamp ±5 min window — stale request rejection
 *   3. HMAC timing-safe comparison — prevents timing oracle attacks
 *   4. API key looked up by public keyId (not raw key) — constant-time resolution
 *   5. Merchant must be active (isActive = true)
 *   6. API key entry must be active and not expired
 *   7. Optional per-merchant IP whitelist enforced
 *   8. Key last-used timestamp updated asynchronously
 */

const crypto       = require('crypto');
const { AppError } = require('@xcg/common');
const { Merchant } = require('@xcg/database');
const { decrypt }  = require('@xcg/crypto');
const { config }   = require('../config');

const logger = require('@xcg/logger').createLogger('merchant-auth');

const NONCE_TTL_SECONDS = 600;      // 10-minute nonce window
const TIMESTAMP_WINDOW  = 300;      // ±5 minutes clock skew tolerance

/**
 * Build canonical string for HMAC signing.
 * Both client SDK and server must produce identical output.
 */
function buildCanonical(method, path, timestamp, nonce, body) {
  const bodyStr  = (body && Object.keys(body).length) ? JSON.stringify(body) : '';
  const bodyHash = crypto.createHash('sha256').update(bodyStr, 'utf8').digest('hex');
  return `${method.toUpperCase()}\n${path}\n${timestamp}\n${nonce}\n${bodyHash}`;
}

/**
 * Factory: returns middleware with Redis client injected.
 * @param {object} redisClient - IORedis instance
 */
function merchantApiAuth(redisClient) {
  return async function (req, res, next) {
    try {
      // ── 1. Extract & validate required headers ─────────────────────────────
      const keyId     = req.headers['x-api-key'];
      const nonce     = req.headers['x-nonce'];
      const timestamp = req.headers['x-timestamp'];
      const signature = req.headers['x-signature'];

      if (!keyId || !nonce || !timestamp || !signature) {
        throw AppError.unauthorized('Missing required authentication headers');
      }

      // ── 2. Timestamp window check (prevents stale request replay) ──────────
      const tsNum = parseInt(timestamp, 10);
      if (!Number.isFinite(tsNum)) {
        throw AppError.unauthorized('Invalid timestamp format');
      }
      const drift = Math.abs(Math.floor(Date.now() / 1000) - tsNum);
      if (drift > TIMESTAMP_WINDOW) {
        throw AppError.unauthorized('Request timestamp outside acceptable window');
      }

      // ── 3. Nonce uniqueness check (Redis — survives restarts + multi-instance) ──
      // Using SET NX (only set if not exists) as atomic check-and-set
      const nonceKey  = `xcg:nonce:${keyId}:${nonce}`;
      const isNew     = await redisClient.set(nonceKey, '1', 'EX', NONCE_TTL_SECONDS, 'NX');
      if (isNew === null) {
        logger.warn('Nonce replay attack detected', { keyId, ip: req.ip });
        throw AppError.unauthorized('Nonce already used');
      }

      // ── 4. Resolve keyId → merchant ────────────────────────────────────────
      const merchant = await Merchant.findOne({
        'apiKeys.keyId': keyId,
        isActive: true,
      }).lean();

      if (!merchant) {
        throw AppError.unauthorized('Invalid API key');
      }

      // Find the specific key entry
      const keyEntry = merchant.apiKeys.find((k) => k.keyId === keyId && k.isActive);
      if (!keyEntry) {
        throw AppError.unauthorized('API key is inactive or revoked');
      }

      // Check key expiry
      if (keyEntry.expiresAt && new Date(keyEntry.expiresAt) < new Date()) {
        throw AppError.unauthorized('API key has expired');
      }

      // ── 5. Optional: per-merchant IP whitelist ─────────────────────────────
      if (merchant.ipWhitelistEnabled && merchant.ipWhitelist.length > 0) {
        const clientIp = (req.ip || '').replace(/^::ffff:/, '');
        if (!merchant.ipWhitelist.includes(clientIp)) {
          logger.warn('Merchant IP whitelist rejection', {
            merchantId: String(merchant._id),
            clientIp,
          });
          throw AppError.forbidden('Request IP not allowed');
        }
      }

      // ── 6. Decrypt API secret and verify HMAC ─────────────────────────────
      // apiSecret is AES-256-GCM encrypted in DB (never stored plaintext)
      let apiSecret;
      try {
        apiSecret = decrypt(keyEntry.apiSecret); // Uses MASTER_ENCRYPTION_KEY from env
      } catch (err) {
        logger.error('Failed to decrypt merchant API secret', {
          merchantId: String(merchant._id),
          error: err.message,
        });
        throw AppError.internalError('Authentication system error');
      }

      const canonical = buildCanonical(req.method, req.path, timestamp, nonce, req.body);
      const expected  = crypto.createHmac('sha256', apiSecret).update(canonical).digest('hex');

      // Zero the decrypted secret ASAP
      apiSecret = null;

      // Timing-safe comparison — prevents timing oracle attacks
      const sigBuf = Buffer.from(signature, 'hex');
      const expBuf = Buffer.from(expected,  'hex');

      if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
        logger.warn('Invalid HMAC signature', {
          merchantId: String(merchant._id),
          ip: req.ip,
          path: req.path,
        });
        throw AppError.unauthorized('Invalid signature');
      }

      // ── 7. Attach merchant + update last-used async ────────────────────────
      req.merchant  = merchant;
      req.apiKeyId  = keyId;

      // Fire-and-forget: update lastUsedAt (don't block the request)
      Merchant.updateOne(
        { _id: merchant._id, 'apiKeys.keyId': keyId },
        { $set: { 'apiKeys.$.lastUsedAt': new Date() } },
      ).catch((err) => logger.debug('Failed to update lastUsedAt', { error: err.message }));

      next();
    } catch (err) {
      next(err);
    }
  };
}

module.exports = merchantApiAuth;
