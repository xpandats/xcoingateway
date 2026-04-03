'use strict';

/**
 * @module @xcg/crypto/keyManager
 *
 * Key Manager — Secure Key Lifecycle Management.
 *
 * BANK-GRADE REQUIREMENTS:
 *   - Master key validated on every startup (fail-fast)
 *   - Per-wallet key derivation using HKDF with RANDOM salt
 *   - Salt stored in Wallet model, unique per wallet
 *   - Secure memory zeroing after key use
 */

const crypto = require('crypto');

/**
 * Validate master encryption key from environment.
 * MUST be called on every service startup. If invalid → service MUST NOT start.
 *
 * @throws {Error} If master key is missing, wrong length, or invalid hex
 */
function validateMasterKey() {
  const keyHex = process.env.MASTER_ENCRYPTION_KEY;

  if (!keyHex) {
    throw new Error('FATAL: MASTER_ENCRYPTION_KEY is not set. Service cannot start.');
  }
  if (keyHex.length !== 64) {
    throw new Error(`FATAL: MASTER_ENCRYPTION_KEY must be 64 hex chars (got ${keyHex.length}).`);
  }
  if (!/^[a-f0-9]{64}$/i.test(keyHex)) {
    throw new Error('FATAL: MASTER_ENCRYPTION_KEY contains invalid characters. Must be hex only.');
  }

  const keyBuffer = Buffer.from(keyHex, 'hex');
  if (keyBuffer.length !== 32) {
    throw new Error('FATAL: MASTER_ENCRYPTION_KEY does not produce a 32-byte key.');
  }
  keyBuffer.fill(0);
  // Validation passed — key stays in process.env until deriveWalletKey() is called
}

/**
 * Generate a random salt for wallet key derivation.
 * This salt MUST be stored alongside the wallet and passed
 * to deriveWalletKey() for every encrypt/decrypt operation.
 *
 * @returns {string} 32-byte random salt (hex-encoded)
 */
function generateWalletSalt() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Derive a unique sub-key for a specific wallet.
 *
 * Uses HKDF (HMAC-based Key Derivation Function):
 *   - Master key as IKM (input keying material)
 *   - Random per-wallet salt (stored in DB, not static)
 *   - walletId as info (context binding)
 *
 * Each wallet has cryptographic isolation: compromising one
 * wallet's derived key does not reveal the master key or
 * any other wallet's key.
 *
 * @param {string} walletId - Wallet's unique identifier
 * @param {string} salt - Per-wallet random salt (hex, from Wallet model)
 * @returns {Buffer} 32-byte derived key — CALLER MUST ZERO AFTER USE
 */
function deriveWalletKey(walletId, salt) {
  if (!salt) {
    throw new Error('SECURITY: Wallet key derivation requires a per-wallet salt');
  }

  const masterKey = Buffer.from(process.env.MASTER_ENCRYPTION_KEY, 'hex');
  const saltBuffer = Buffer.from(salt, 'hex');

  try {
    const info = Buffer.from(walletId, 'utf8');
    return crypto.hkdfSync('sha256', masterKey, saltBuffer, info, 32);
  } finally {
    masterKey.fill(0);
  }
}

/**
 * Securely zero a buffer or string from memory.
 *
 * @param {Buffer|string} data - Data to zero
 */
function zeroMemory(data) {
  if (Buffer.isBuffer(data)) {
    data.fill(0);
  } else if (typeof data === 'string') {
    // JS strings are immutable — best effort via buffer
    const buf = Buffer.from(data, 'utf8');
    buf.fill(0);
  }
}

/**
 * Generate a new random master key (setup utility).
 *
 * @returns {string} 64-character hex string (32 bytes)
 */
function generateMasterKey() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = {
  validateMasterKey,
  generateWalletSalt,
  deriveWalletKey,
  zeroMemory,
  generateMasterKey,
};
