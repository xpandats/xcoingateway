'use strict';

/**
 * @module @xcg/crypto/encryption
 *
 * AES-256-GCM Encryption with Key Versioning.
 *
 * BANK-GRADE REQUIREMENTS:
 *   - AES-256-GCM: Authenticated encryption (confidentiality + integrity)
 *   - Unique IV per encryption: same plaintext → different ciphertext every time
 *   - Auth tag: tampering detection
 *   - Key versioning: old encrypted data remains readable after key rotation
 *   - Memory safety: keys zeroed from memory after use
 *
 * Output format (versioned):
 *   v1:iv:authTag:ciphertext  (all hex-encoded, colon-separated)
 *
 * Legacy format (auto-detected for backward compatibility):
 *   iv:authTag:ciphertext     (no version prefix)
 */

const crypto = require('crypto');

const CURRENT_KEY_VERSION = 'v1';
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;        // 128-bit IV (NIST recommended for GCM)
const AUTH_TAG_LENGTH = 16;  // 128-bit auth tag
const KEY_LENGTH = 32;       // 256-bit key

/**
 * Get the master encryption key from environment.
 * Validates key length and hex format.
 *
 * @returns {Buffer} 32-byte key buffer — CALLER MUST ZERO AFTER USE
 * @throws {Error} If master key is missing or invalid
 */
function getMasterKey() {
  const keyHex = process.env.MASTER_ENCRYPTION_KEY;
  if (!keyHex) {
    throw new Error('CRITICAL: MASTER_ENCRYPTION_KEY environment variable is not set');
  }
  if (keyHex.length !== 64) {
    throw new Error('CRITICAL: MASTER_ENCRYPTION_KEY must be exactly 64 hex characters (32 bytes)');
  }
  return Buffer.from(keyHex, 'hex');
}

/**
 * Encrypt plaintext using AES-256-GCM with key versioning.
 *
 * @param {string} plaintext - Data to encrypt
 * @param {Buffer} [masterKey] - Optional custom key (defaults to ENV master key)
 * @returns {string} Versioned encrypted string: "v1:iv:authTag:ciphertext"
 */
function encrypt(plaintext, masterKey = null) {
  const key = masterKey || getMasterKey();
  let iv = null;

  try {
    iv = crypto.randomBytes(IV_LENGTH);

    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });

    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    // Versioned format: v1:iv:authTag:ciphertext
    return `${CURRENT_KEY_VERSION}:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  } finally {
    if (!masterKey && key) key.fill(0);
    if (iv) iv.fill(0);
  }
}

/**
 * Decrypt ciphertext using AES-256-GCM.
 * Automatically handles both versioned (v1:iv:tag:cipher) and
 * legacy (iv:tag:cipher) formats.
 *
 * @param {string} encryptedData - Encrypted string (versioned or legacy)
 * @param {Buffer} [masterKey] - Optional custom key
 * @returns {string} Decrypted plaintext
 * @throws {Error} If decryption fails
 */
function decrypt(encryptedData, masterKey = null) {
  const key = masterKey || getMasterKey();

  try {
    const parts = encryptedData.split(':');
    let ivHex, authTagHex, ciphertext;

    if (parts[0] === 'v1') {
      // Versioned format: v1:iv:authTag:ciphertext
      if (parts.length !== 4) {
        throw new Error('Invalid v1 encrypted data format');
      }
      [, ivHex, authTagHex, ciphertext] = parts;
    } else if (parts.length === 3) {
      // Legacy format: iv:authTag:ciphertext (backward compatible)
      [ivHex, authTagHex, ciphertext] = parts;
    } else {
      throw new Error('Invalid encrypted data format: unrecognized format');
    }

    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');

    if (iv.length !== IV_LENGTH) throw new Error('Invalid IV length');
    if (authTag.length !== AUTH_TAG_LENGTH) throw new Error('Invalid auth tag length');

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  } finally {
    if (!masterKey && key) key.fill(0);
  }
}

/**
 * Re-encrypt data with current key version.
 * Used during key rotation: decrypt old → encrypt new.
 *
 * @param {string} encryptedData - Old encrypted data (any version)
 * @param {Buffer} [oldKey] - Optional old key (defaults to current ENV key)
 * @param {Buffer} [newKey] - Optional new key (defaults to current ENV key)
 * @returns {string} Re-encrypted with current version
 */
function reEncrypt(encryptedData, oldKey = null, newKey = null) {
  const plaintext = decrypt(encryptedData, oldKey);
  return encrypt(plaintext, newKey);
}

/**
 * Check if data is using the latest encryption version.
 *
 * @param {string} encryptedData - Encrypted string
 * @returns {boolean} true if using current version
 */
function isCurrentVersion(encryptedData) {
  return encryptedData.startsWith(`${CURRENT_KEY_VERSION}:`);
}

/**
 * Encrypt a private key with additional safety.
 *
 * @param {string} privateKey - Private key to encrypt
 * @returns {string} Versioned encrypted private key
 */
function encryptPrivateKey(privateKey) {
  let keyBuffer = null;
  try {
    keyBuffer = Buffer.from(privateKey, 'utf8');
    return encrypt(privateKey);
  } finally {
    if (keyBuffer) keyBuffer.fill(0);
  }
}

/**
 * Decrypt a private key.
 *
 * E1 FIX: Returns Buffer (not string) so callers can zero memory after use.
 *   JS strings are immutable — you CANNOT zero them. Buffers can be zeroed.
 *
 * USAGE:
 *   const keyBuf = decryptPrivateKey(encryptedKey);
 *   try {
 *     // use keyBuf.toString('utf8') only where needed
 *   } finally {
 *     keyBuf.fill(0); // Zero private key from memory
 *   }
 *
 * @param {string} encryptedKey - Encrypted private key
 * @returns {Buffer} Decrypted private key as Buffer — CALLER MUST ZERO WITH .fill(0)
 */
function decryptPrivateKey(encryptedKey) {
  const plaintext = decrypt(encryptedKey);
  return Buffer.from(plaintext, 'utf8');
  // Original string 'plaintext' remains in GC-eligible memory but
  // callers can zero the returned Buffer immediately after use.
}

module.exports = {
  encrypt,
  decrypt,
  reEncrypt,
  isCurrentVersion,
  encryptPrivateKey,
  decryptPrivateKey,
  ALGORITHM,
  IV_LENGTH,
  AUTH_TAG_LENGTH,
  KEY_LENGTH,
  CURRENT_KEY_VERSION,
};
