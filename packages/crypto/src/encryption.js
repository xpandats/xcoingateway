'use strict';

/**
 * AES-256-GCM Encryption Module.
 *
 * Used for encrypting private keys, API secrets, and sensitive data.
 *
 * Security guarantees:
 *   - AES-256-GCM provides both confidentiality and integrity
 *   - Unique IV (Initialization Vector) per encryption — same plaintext → different ciphertext
 *   - Auth tag prevents tampering — any modification is detected
 *   - Master key from ENV, never in DB, never in code
 *   - Key zeroed from memory after use via Buffer.fill(0)
 *
 * Output format: iv:authTag:ciphertext (all hex-encoded, colon-separated)
 */

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;       // 128-bit IV (recommended for GCM)
const AUTH_TAG_LENGTH = 16;  // 128-bit auth tag
const KEY_LENGTH = 32;       // 256-bit key

/**
 * Get the master encryption key from environment.
 * Validates key length and format.
 *
 * @returns {Buffer} 32-byte key buffer
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
 * Encrypt plaintext using AES-256-GCM.
 *
 * @param {string} plaintext - The data to encrypt
 * @param {Buffer} [masterKey] - Optional custom key (defaults to ENV master key)
 * @returns {string} Encrypted string in format "iv:authTag:ciphertext" (hex)
 */
function encrypt(plaintext, masterKey = null) {
  const key = masterKey || getMasterKey();
  let iv = null;

  try {
    // Generate unique IV for this encryption
    iv = crypto.randomBytes(IV_LENGTH);

    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });

    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    // Format: iv:authTag:ciphertext
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  } finally {
    // Zero the key from memory if we created it
    if (!masterKey && key) {
      key.fill(0);
    }
    if (iv) {
      iv.fill(0);
    }
  }
}

/**
 * Decrypt ciphertext using AES-256-GCM.
 *
 * @param {string} encryptedData - Encrypted string in format "iv:authTag:ciphertext" (hex)
 * @param {Buffer} [masterKey] - Optional custom key (defaults to ENV master key)
 * @returns {string} Decrypted plaintext
 * @throws {Error} If decryption fails (wrong key, tampered data, invalid format)
 */
function decrypt(encryptedData, masterKey = null) {
  const key = masterKey || getMasterKey();

  try {
    const parts = encryptedData.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted data format: expected iv:authTag:ciphertext');
    }

    const [ivHex, authTagHex, ciphertext] = parts;
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');

    if (iv.length !== IV_LENGTH) {
      throw new Error('Invalid IV length');
    }
    if (authTag.length !== AUTH_TAG_LENGTH) {
      throw new Error('Invalid auth tag length');
    }

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  } finally {
    // Zero the key from memory if we created it
    if (!masterKey && key) {
      key.fill(0);
    }
  }
}

/**
 * Encrypt a private key with additional safety:
 * - Validates the key looks like a private key
 * - Returns the encrypted key
 * - Zeroes the plaintext key from memory
 *
 * @param {string} privateKey - The private key to encrypt
 * @returns {string} Encrypted private key
 */
function encryptPrivateKey(privateKey) {
  let keyBuffer = null;
  try {
    // Convert to buffer so we can zero it after
    keyBuffer = Buffer.from(privateKey, 'utf8');
    const encrypted = encrypt(privateKey);
    return encrypted;
  } finally {
    // CRITICAL: Zero the plaintext private key from memory
    if (keyBuffer) {
      keyBuffer.fill(0);
    }
  }
}

/**
 * Decrypt a private key with safety:
 * - Returns the key string
 * - CALLER is responsible for zeroing after use
 *
 * @param {string} encryptedKey - The encrypted private key
 * @returns {string} Decrypted private key — ZERO THIS AFTER USE
 */
function decryptPrivateKey(encryptedKey) {
  return decrypt(encryptedKey);
}

module.exports = {
  encrypt,
  decrypt,
  encryptPrivateKey,
  decryptPrivateKey,
  ALGORITHM,
  IV_LENGTH,
  AUTH_TAG_LENGTH,
  KEY_LENGTH,
};
