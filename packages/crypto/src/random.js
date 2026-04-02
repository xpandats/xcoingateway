'use strict';

/**
 * Secure random generation utilities.
 * Uses crypto.randomBytes for cryptographically secure randomness.
 */

const crypto = require('crypto');

/**
 * Generate a cryptographically secure random hex string.
 *
 * @param {number} bytes - Number of random bytes (output will be 2x chars in hex)
 * @returns {string} Hex-encoded random string
 */
function randomHex(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

/**
 * Generate a UUID v4 (for idempotency keys, nonces, etc.).
 *
 * @returns {string} UUID v4 string
 */
function randomUUID() {
  return crypto.randomUUID();
}

/**
 * Generate a secure API key (64 hex characters = 32 bytes of entropy).
 *
 * @returns {string} 64-character hex API key
 */
function generateApiKey() {
  return randomHex(32);
}

/**
 * Generate a secure API secret (64 hex characters).
 * This is the secret used for HMAC signing.
 *
 * @returns {string} 64-character hex API secret
 */
function generateApiSecret() {
  return randomHex(32);
}

/**
 * Generate a webhook signing secret.
 *
 * @returns {string} Webhook secret prefixed with 'whsec_' for easy identification
 */
function generateWebhookSecret() {
  return `whsec_${randomHex(32)}`;
}

/**
 * Generate a unique decimal offset for invoice amounts.
 * Range: 0.000001 to 0.009999
 * Precision: 6 decimal places (USDT standard)
 *
 * @returns {number} Random offset between 0.000001 and 0.009999
 */
function generateUniqueAmountOffset() {
  // Generate random integer between 1 and 9999
  const min = 1;
  const max = 9999;
  const range = max - min + 1;

  // Use crypto.randomInt for uniform distribution
  const randomInt = crypto.randomInt(min, max + 1);

  // Convert to 6 decimal places: 1 → 0.000001, 9999 → 0.009999
  return randomInt / 1000000;
}

module.exports = {
  randomHex,
  randomUUID,
  generateApiKey,
  generateApiSecret,
  generateWebhookSecret,
  generateUniqueAmountOffset,
};
