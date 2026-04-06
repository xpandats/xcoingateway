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
 *
 * GAP 2 FIX — Redis caching for hot-path merchant lookups:
 *   merchantApiAuth is called on EVERY merchant API request. Without caching,
 *   each call hits MongoDB to load the full merchant document.
 *   Fix: Cache (keyId → merchant auth data) in Redis with a 5-minute TTL.
 *   Cache stores ONLY: keyId, keyHash, apiSecret (encrypted), isActive, expiresAt,
 *   merchantId, ipWhitelistEnabled, ipWhitelist — the minimum needed for auth.
 *   NOT cached: apiKeys array for other keyIds, stats, webhookSecret, business data.
 *   Invalidated by: key revoke, merchant deactivate, key expiry update.
 *
 * GAP 3 FIX — .lean() bypasses select:false on apiKeys sub-fields:
 *   The Merchant schema sets select:false on apiKeys[].keyHash and apiKeys[].apiSecret
 *   to protect them in general queries. However, .lean() bypasses Mongoose
 *   field selection — all schema-level select:false fields ARE returned in .lean().
 *   Fix: explicit .select() projection that names exactly what we need.
 *   This ensures only the authenticated key's data loads into memory, not all keys.
 */

const crypto        = require('crypto');
const { AppError }  = require('@xcg/common');
const { Merchant, ApiRequestLog } = require('@xcg/database');
const { decrypt }   = require('@xcg/crypto');
const { UsedNonce } = require('@xcg/database');
const { config }    = require('../config');
const cache         = require('../utils/cache');

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
 * Load merchant auth data for a given keyId.
 *
 * GAP 3 FIX: Uses explicit .select() projection instead of .lean() without projection.
 *   Without an explicit projection, .lean() returns ALL fields including the full
 *   apiKeys array for every key on the merchant — even those with select:false.
 *   The projection below fetches ONLY the matched API key subdocument and the
 *   minimum merchant-level fields required for auth.
 *
 * GAP 2 FIX: Result is cached in Redis (TTL 5 min) to avoid a DB hit on every request.
 *
 * @param {string} keyId - Public API key identifier
 * @param {object|null} redis - IORedis client
 * @returns {Promise<{ merchant, keyEntry } | null>}
 */
async function loadMerchantForAuth(keyId, redis) {
  const cacheKey = cache.KEY.merchantApiAuth(keyId);

  // ── Cache read ───────────────────────────────────────────────────────────────
  const cached = await cache.get(redis, cacheKey);
  if (cached) {
    return cached;  // { merchant, keyEntry } — already the shape we need
  }

  // ── DB read with explicit projection (Gap 3 fix) ─────────────────────────────
  // We use $elemMatch to fetch ONLY the specific API key subdocument, not all keys.
  // This prevents loading other merchant apiKey secrets into memory.
  const merchant = await Merchant.findOne(
    {
      'apiKeys.keyId': keyId,
      isActive: true,
    },
    {
      // Merchant-level auth fields only
      _id:                1,
      isActive:           1,
      ipWhitelistEnabled: 1,
      ipWhitelist:        1,
      // Single matched API key only — $elemMatch in projection returns array of 1
      apiKeys: { $elemMatch: { keyId } },
    },
  ).lean();

  if (!merchant) return null;

  const keyEntry = merchant.apiKeys?.[0];
  if (!keyEntry) return null;

  const result = { merchant, keyEntry };

  // ── Cache write ──────────────────────────────────────────────────────────────
  // Security note: keyEntry.apiSecret is AES-256-GCM encrypted at rest.
  // We cache the encrypted blob (not the plaintext) — same security level as DB.
  // The decryption still happens per-request (cheap, and avoids caching plaintext).
  await cache.set(redis, cacheKey, result, cache.TTL.MERCHANT_PROFILE);

  return result;
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

      // ── 3. Nonce uniqueness check (Redis preferred; DB fallback for dev/test) ──
      if (redisClient) {
        // Production path: Redis SET NX — single atomic command, no race window.
        const nonceKey = `xcg:nonce:${keyId}:${nonce}`;
        const isNew    = await redisClient.set(nonceKey, '1', 'EX', NONCE_TTL_SECONDS, 'NX');
        if (isNew === null) {
          logger.warn('Nonce replay attack detected (redis)', { keyId, ip: req.ip });
          throw AppError.unauthorized('Nonce already used');
        }
      } else {
        // Fallback path: atomic MongoDB insert — NO race condition.
        // The unique compound index { nonce, merchantId } on UsedNonce enforces
        // uniqueness at the DB level. If the nonce already exists, create() throws
        // error code 11000 (duplicate key). One round-trip, zero race window.
        const nonceKey = `${keyId}:${nonce}`;
        try {
          await UsedNonce.create({
            nonce:      nonceKey,
            merchantId: '000000000000000000000000', // placeholder — uniqueness enforced on nonce+merchantId compound
            usedAt:     new Date(),
          });
        } catch (err) {
          if (err.code === 11000) {
            logger.warn('Nonce replay attack detected (db)', { keyId, ip: req.ip });
            throw AppError.unauthorized('Nonce already used');
          }
          logger.error('Nonce store write failed — blocking request', { error: err.message, keyId });
          throw AppError.internalError('Authentication system error');
        }
      }

      // ── 4. Resolve keyId → merchant (with caching + projection fix) ────────
      const authData = await loadMerchantForAuth(keyId, redisClient);

      if (!authData) {
        throw AppError.unauthorized('Invalid API key');
      }

      const { merchant, keyEntry } = authData;

      // Verify key is still active (double-check after potential cache hit)
      if (!keyEntry.isActive) {
        throw AppError.unauthorized('API key is inactive or revoked');
      }

      // Check key expiry
      if (keyEntry.expiresAt && new Date(keyEntry.expiresAt) < new Date()) {
        // Invalidate cache — expired key may have been cached as active
        await cache.del(redisClient, cache.KEY.merchantApiAuth(keyId));
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
      // apiSecret is AES-256-GCM encrypted in DB (and cached as encrypted blob).
      // Decryption happens freshly per-request — we never cache the plaintext secret.
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

      // Zero the decrypted secret immediately — never let it linger in memory
      apiSecret = null;

      // Timing-safe comparison — prevents timing oracle attacks
      let sigBuf, expBuf;
      try {
        sigBuf = Buffer.from(signature, 'hex');
        expBuf = Buffer.from(expected,  'hex');
      } catch {
        throw AppError.unauthorized('Invalid signature format');
      }

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

      // Fire-and-forget: update lastUsedAt (don't delay the request)
      Merchant.updateOne(
        { _id: merchant._id, 'apiKeys.keyId': keyId },
        { $set: { 'apiKeys.$.lastUsedAt': new Date() } },
      ).catch((err) => logger.debug('Failed to update lastUsedAt', { error: err.message }));

      // ── 8. Log API request for forensics (non-blocking) ────────────────────
      const requestStartTime = Date.now();
      res.on('finish', () => {
        ApiRequestLog.create({
          merchantId:   String(merchant._id),
          apiKeyId:     keyId,
          method:       req.method,
          endpoint:     req.originalUrl || req.path,
          ipAddress:    req.ip || 'unknown',
          userAgent:    req.headers['user-agent'] || null,
          statusCode:   res.statusCode,
          responseTimeMs: Date.now() - requestStartTime,
          hmacValid:    true,
          idempotencyKey: req.headers['x-idempotency-key'] || null,
        }).catch((e) => logger.debug('ApiRequestLog write failed', { error: e.message }));
      });

      next();
    } catch (err) {
      // Log failed auth attempt (non-blocking)
      const failedKeyId = req.headers?.['x-api-key'] || 'unknown';
      ApiRequestLog.create({
        apiKeyId:     failedKeyId,
        method:       req.method,
        endpoint:     req.originalUrl || req.path,
        ipAddress:    req.ip || 'unknown',
        userAgent:    req.headers?.['user-agent'] || null,
        statusCode:   err.statusCode || 401,
        hmacValid:    false,
        error:        err.message,
      }).catch(() => {});
      next(err);
    }
  };
}

module.exports = merchantApiAuth;
