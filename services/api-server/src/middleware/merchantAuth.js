'use strict';

/**
 * @module middleware/apiHmac
 *
 * Merchant API HMAC Authentication Middleware.
 *
 * BANK-GRADE REQUIREMENTS:
 *   - HMAC-SHA256 signature validation on every merchant API request
 *   - Timestamp tolerance window (±30 seconds) — blocks replay attacks
 *   - Nonce deduplication (stored in MongoDB with TTL) — blocks replay reuse
 *   - Per-merchant API key + secret verification
 *
 * Request headers required:
 *   x-api-key       — Public merchant API key ID
 *   x-timestamp     — Unix timestamp in seconds (must be within tolerance)
 *   x-nonce         — Random UUID (used only once within TTL window)
 *   x-signature     — HMAC-SHA256(method+url+timestamp+nonce+body, apiSecret)
 *
 * Signature construction (canonical string):
 *   METHOD\nURL_PATH\nTIMESTAMP\nNONCE\nBODY_SHA256_HEX
 */

const crypto = require('crypto');
const { Merchant, UsedNonce } = require('@xcg/database');
const { AppError, ErrorCodes, constants } = require('@xcg/common');
const { createLogger } = require('@xcg/logger');
const { decrypt } = require('@xcg/crypto');
const { config } = require('../config');

const { AUTH } = constants;
const logger = createLogger('api-hmac');

/**
 * Build the canonical string that the merchant signed.
 *
 * @param {object} req - Express request
 * @param {string} timestamp - x-timestamp header
 * @param {string} nonce - x-nonce header
 * @returns {string} Canonical string for HMAC computation
 */
function _buildCanonicalString(req, timestamp, nonce) {
  const method = req.method.toUpperCase();
  const urlPath = req.originalUrl || req.url;

  // D4: Sort keys for deterministic body hash (JSON key order is insertion-order in JS)
  // Merchants MUST sort their body keys too — document this in API docs.
  const sortedBody = req.body ? JSON.stringify(req.body, Object.keys(req.body).sort()) : '';
  const bodyHash = crypto
    .createHash('sha256')
    .update(sortedBody)
    .digest('hex');

  return `${method}\n${urlPath}\n${timestamp}\n${nonce}\n${bodyHash}`;
}

/**
 * Middleware: Validate timestamp within tolerance window.
 * Blocks requests older than TIMESTAMP_TOLERANCE_SECONDS.
 */
function validateTimestamp(req, res, next) {
  const timestampHeader = req.headers['x-timestamp'];

  if (!timestampHeader) {
    return next(AppError.badRequest('x-timestamp header is required', ErrorCodes.MERCHANT_TIMESTAMP_EXPIRED));
  }

  const requestTime = parseInt(timestampHeader, 10);
  if (isNaN(requestTime)) {
    return next(AppError.badRequest('x-timestamp must be a Unix timestamp (seconds)', ErrorCodes.MERCHANT_TIMESTAMP_EXPIRED));
  }

  const now = Math.floor(Date.now() / 1000);
  const diff = Math.abs(now - requestTime);

  if (diff > AUTH.TIMESTAMP_TOLERANCE_SECONDS) {
    logger.warn('Request timestamp out of tolerance', {
      requestId: req.requestId,
      ip: req.ip,
      requestTime,
      serverTime: now,
      diffSeconds: diff,
    });
    return next(AppError.badRequest(
      `Request timestamp is ${diff}s from server time. Maximum tolerance is ${AUTH.TIMESTAMP_TOLERANCE_SECONDS}s.`,
      ErrorCodes.MERCHANT_TIMESTAMP_EXPIRED,
    ));
  }

  next();
}

/**
 * Full HMAC authentication middleware for merchant API routes.
 * Combines: API key lookup → timestamp → nonce → HMAC validation.
 */
async function merchantAuth(req, res, next) {
  try {
    const apiKeyId = req.headers['x-api-key'];
    const timestamp = req.headers['x-timestamp'];
    const nonce = req.headers['x-nonce'];
    const signature = req.headers['x-signature'];

    // All 4 headers required
    if (!apiKeyId || !timestamp || !nonce || !signature) {
      return next(AppError.unauthorized(
        'Merchant API requires: x-api-key, x-timestamp, x-nonce, x-signature headers',
        ErrorCodes.MERCHANT_API_KEY_INVALID,
      ));
    }

    // 1. Validate timestamp (anti-replay: time window)
    const requestTime = parseInt(timestamp, 10);
    const now = Math.floor(Date.now() / 1000);
    if (isNaN(requestTime) || Math.abs(now - requestTime) > AUTH.TIMESTAMP_TOLERANCE_SECONDS) {
      return next(AppError.badRequest(
        `Request timestamp expired or too far in the future. Tolerance: ${AUTH.TIMESTAMP_TOLERANCE_SECONDS}s.`,
        ErrorCodes.MERCHANT_TIMESTAMP_EXPIRED,
      ));
    }

    // 2. Lookup merchant by apiKeyId
    const merchant = await Merchant.findOne({
      'apiKeys.keyId': apiKeyId,
      isActive: true,
    });

    if (!merchant) {
      return next(AppError.unauthorized('Invalid API key', ErrorCodes.MERCHANT_API_KEY_INVALID));
    }

    // D6: Check API key expiry
    const apiKey = merchant.apiKeys.find(
      (k) => k.keyId === apiKeyId
           && k.isActive
           && (k.expiresAt === null || k.expiresAt === undefined || k.expiresAt > new Date()),
    );
    if (!apiKey) {
      return next(AppError.unauthorized('API key is inactive, expired, or not found', ErrorCodes.MERCHANT_API_KEY_INVALID));
    }

    // Merchant IP whitelist check (if enabled)
    if (merchant.ipWhitelistEnabled && merchant.ipWhitelist.length > 0) {
      if (!merchant.ipWhitelist.includes(req.ip)) {
        logger.warn('Merchant API request from non-whitelisted IP', {
          merchantId: merchant._id,
          ip: req.ip,
          whitelist: merchant.ipWhitelist,
        });
        return next(AppError.forbidden('IP address not whitelisted for this merchant', ErrorCodes.AUTH_IP_NOT_WHITELISTED));
      }
    }

    // 3. Validate nonce (anti-replay: exact reuse prevention)
    const isDuplicateNonce = await UsedNonce.exists({ nonce, merchantId: merchant._id });
    if (isDuplicateNonce) {
      logger.warn('Nonce reuse detected', {
        requestId: req.requestId,
        ip: req.ip,
        merchantId: merchant._id,
        nonce,
      });
      return next(AppError.badRequest('Nonce already used. Generate a new nonce per request.', ErrorCodes.MERCHANT_NONCE_REUSED));
    }

    // 4. Validate HMAC signature
    const decryptedSecret = decrypt(apiKey.apiSecret);
    const canonicalString = _buildCanonicalString(req, timestamp, nonce);
    const expectedSignature = crypto
      .createHmac('sha256', decryptedSecret)
      .update(canonicalString)
      .digest('hex');

    // Constant-time comparison to prevent timing attacks
    const sigBuffer = Buffer.from(signature, 'hex');
    const expectedBuffer = Buffer.from(expectedSignature, 'hex');

    if (sigBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
      logger.warn('HMAC signature mismatch', {
        requestId: req.requestId,
        ip: req.ip,
        merchantId: merchant._id,
        apiKeyId,
      });
      return next(AppError.unauthorized('Invalid request signature', ErrorCodes.MERCHANT_HMAC_INVALID));
    }

    // 5. Store nonce (TTL auto-expires via MongoDB index)
    // D3: If nonce storage fails, the request MUST be rejected to prevent replay.
    try {
      await UsedNonce.create({
        nonce,
        merchantId: merchant._id,
      });
    } catch (nonceErr) {
      logger.error('SECURITY: Nonce storage failed — blocking request to prevent replay', {
        error: nonceErr.message,
        requestId: req.requestId,
        merchantId: merchant._id,
      });
      return next(AppError.internal('Request could not be processed securely. Please retry.'));
    }

    // 6. Update key last-used timestamp (non-blocking)
    Merchant.updateOne(
      { '_id': merchant._id, 'apiKeys.keyId': apiKeyId },
      { '$set': { 'apiKeys.$.lastUsedAt': new Date() } },
    ).catch((err) => logger.error('Failed to update apiKey lastUsedAt', { error: err.message }));

    // 7. Attach merchant to request
    // CRITICAL: include raw ObjectId as _id for downstream DB queries
    // Controllers must NOT have to cast merchantId string → ObjectId themselves
    req.merchant = {
      _id:          merchant._id,              // ← Raw Mongoose ObjectId — use in DB queries
      merchantId:   merchant._id.toString(),   // ← String — use in JSON responses
      businessName: merchant.businessName,
      apiKeyId,
      permissions:  apiKey.permissions,
    };

    next();
  } catch (err) {
    next(err);
  }
}

module.exports = { merchantAuth, validateTimestamp };
