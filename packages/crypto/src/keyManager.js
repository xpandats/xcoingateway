'use strict';

/**
 * Key Manager — Secure key lifecycle management.
 *
 * Handles:
 *   - Master key validation on startup
 *   - Key derivation per wallet (so each wallet has a unique encryption context)
 *   - Secure key access with audit logging hooks
 *   - Key zeroing utilities
 */

const crypto = require('crypto');

/**
 * Validate that the master encryption key is properly configured.
 * Call this on every service startup. If invalid, the service MUST NOT start.
 *
 * @throws {Error} If master key is missing, wrong length, or invalid hex
 */
function validateMasterKey() {
  const keyHex = process.env.MASTER_ENCRYPTION_KEY;

  if (!keyHex) {
    throw new Error('FATAL: MASTER_ENCRYPTION_KEY is not set. Service cannot start.');
  }

  if (keyHex.length !== 64) {
    throw new Error(`FATAL: MASTER_ENCRYPTION_KEY must be 64 hex chars (got ${keyHex.length}). Service cannot start.`);
  }

  if (!/^[a-f0-9]{64}$/i.test(keyHex)) {
    throw new Error('FATAL: MASTER_ENCRYPTION_KEY contains invalid characters. Must be hex only.');
  }

  // Verify it creates a valid 32-byte buffer
  const keyBuffer = Buffer.from(keyHex, 'hex');
  if (keyBuffer.length !== 32) {
    throw new Error('FATAL: MASTER_ENCRYPTION_KEY does not produce a 32-byte key.');
  }
  keyBuffer.fill(0); // Zero immediately after validation
}

/**
 * Derive a unique sub-key for a specific wallet.
 * Uses HKDF (HMAC-based Key Derivation Function) to derive wallet-specific keys
 * from the master key, ensuring each wallet has cryptographic isolation.
 *
 * @param {string} walletId - The wallet's unique identifier
 * @param {string} [context='wallet-encryption'] - Context string for key derivation
 * @returns {Buffer} 32-byte derived key — CALLER MUST ZERO AFTER USE
 */
function deriveWalletKey(walletId, context = 'wallet-encryption') {
  const masterKey = Buffer.from(process.env.MASTER_ENCRYPTION_KEY, 'hex');

  try {
    // HKDF: Extract-and-Expand
    const salt = Buffer.from(context, 'utf8');
    const info = Buffer.from(walletId, 'utf8');

    return crypto.hkdfSync('sha256', masterKey, salt, info, 32);
  } finally {
    masterKey.fill(0);
  }
}

/**
 * Securely zero a buffer or string from memory.
 * Call this after using any sensitive data (private keys, decrypted secrets).
 *
 * @param {Buffer|string} data - Data to zero
 */
function zeroMemory(data) {
  if (Buffer.isBuffer(data)) {
    data.fill(0);
  } else if (typeof data === 'string') {
    // Strings are immutable in JS — best effort is to create and zero a buffer
    // This doesn't guarantee the original string is zeroed (V8 may have copies)
    // But it's the best we can do in Node.js without native addons
    const buf = Buffer.from(data, 'utf8');
    buf.fill(0);
  }
}

/**
 * Generate a new random master key.
 * Use this utility to generate initial master keys during setup.
 * The key should be stored securely in environment variables.
 *
 * @returns {string} 64-character hex string (32 bytes)
 */
function generateMasterKey() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = {
  validateMasterKey,
  deriveWalletKey,
  zeroMemory,
  generateMasterKey,
};
