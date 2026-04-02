'use strict';

/**
 * HMAC-SHA256 Signing Module.
 *
 * Used for:
 *   - Merchant API request signatures (prevents tampering + replay)
 *   - Webhook payload signatures (merchant verifies authenticity)
 *   - Internal queue message signing (service-to-service trust)
 *
 * All HMAC operations use SHA-256.
 */

const crypto = require('crypto');

/**
 * Create HMAC-SHA256 signature for data.
 *
 * @param {string} data - Data to sign (stringified JSON, or concatenated fields)
 * @param {string} secret - HMAC secret key
 * @returns {string} Hex-encoded HMAC signature
 */
function createSignature(data, secret) {
  if (!data || !secret) {
    throw new Error('HMAC signing requires both data and secret');
  }
  return crypto.createHmac('sha256', secret).update(data, 'utf8').digest('hex');
}

/**
 * Verify HMAC-SHA256 signature.
 * Uses timing-safe comparison to prevent timing attacks.
 *
 * @param {string} data - Original data that was signed
 * @param {string} signature - The signature to verify (hex)
 * @param {string} secret - HMAC secret key
 * @returns {boolean} true if signature is valid
 */
function verifySignature(data, signature, secret) {
  if (!data || !signature || !secret) {
    return false;
  }

  const expected = createSignature(data, secret);

  // Timing-safe comparison: prevents attackers from guessing the signature
  // byte-by-byte by measuring response time differences
  const expectedBuffer = Buffer.from(expected, 'hex');
  const actualBuffer = Buffer.from(signature, 'hex');

  if (expectedBuffer.length !== actualBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(expectedBuffer, actualBuffer);
}

/**
 * Create signature for a merchant API request.
 * Signs: timestamp + nonce + method + path + body
 *
 * @param {object} params
 * @param {string} params.timestamp - Unix timestamp in seconds
 * @param {string} params.nonce - UUID nonce (one-time use)
 * @param {string} params.method - HTTP method (GET, POST, etc.)
 * @param {string} params.path - Request path (e.g., /api/v1/invoices)
 * @param {string} params.body - Request body (stringified JSON, or empty string)
 * @param {string} params.apiSecret - Merchant's API secret
 * @returns {string} Hex-encoded HMAC signature
 */
function signMerchantRequest({ timestamp, nonce, method, path, body, apiSecret }) {
  const payload = `${timestamp}.${nonce}.${method.toUpperCase()}.${path}.${body || ''}`;
  return createSignature(payload, apiSecret);
}

/**
 * Verify a merchant API request signature.
 *
 * @param {object} params - Same as signMerchantRequest + signature
 * @param {string} params.signature - The signature from request header
 * @returns {boolean} true if valid
 */
function verifyMerchantRequest({ timestamp, nonce, method, path, body, apiSecret, signature }) {
  const payload = `${timestamp}.${nonce}.${method.toUpperCase()}.${path}.${body || ''}`;
  return verifySignature(payload, signature, apiSecret);
}

/**
 * Create signature for a webhook payload.
 * Merchant uses this to verify the webhook came from us.
 *
 * @param {string} payload - Stringified webhook payload
 * @param {string} webhookSecret - Merchant's webhook secret
 * @returns {string} Hex-encoded HMAC signature
 */
function signWebhookPayload(payload, webhookSecret) {
  return createSignature(payload, webhookSecret);
}

/**
 * Create signature for internal queue messages.
 * Ensures messages between services haven't been tampered with.
 *
 * @param {object} message - The queue message object
 * @returns {string} Hex-encoded HMAC signature
 */
function signQueueMessage(message) {
  const secret = process.env.INTERNAL_HMAC_SECRET;
  if (!secret) {
    throw new Error('CRITICAL: INTERNAL_HMAC_SECRET environment variable is not set');
  }
  const data = JSON.stringify(message);
  return createSignature(data, secret);
}

/**
 * Verify internal queue message signature.
 *
 * @param {object} message - The queue message (without _signature field)
 * @param {string} signature - The signature to verify
 * @returns {boolean} true if valid
 */
function verifyQueueMessage(message, signature) {
  const secret = process.env.INTERNAL_HMAC_SECRET;
  if (!secret) return false;
  const data = JSON.stringify(message);
  return verifySignature(data, signature, secret);
}

module.exports = {
  createSignature,
  verifySignature,
  signMerchantRequest,
  verifyMerchantRequest,
  signWebhookPayload,
  signQueueMessage,
  verifyQueueMessage,
};
