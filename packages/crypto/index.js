'use strict';

/**
 * @module @xcg/crypto
 *
 * Cryptographic utilities for XCoinGateway.
 *
 * Exports:
 *   Encryption: encrypt, decrypt, reEncrypt, isCurrentVersion, encryptPrivateKey, decryptPrivateKey
 *   HMAC:       createHmacSignature, verifyHmacSignature
 *   KeyManager: validateMasterKey, generateWalletSalt, deriveWalletKey, zeroMemory, generateMasterKey
 *   Random:     randomHex, randomUUID, generateApiKey, generateApiSecret, generateWebhookSecret, generateUniqueAmountOffset
 */

const encryption = require('./src/encryption');
const hmac = require('./src/hmac');
const keyManager = require('./src/keyManager');
const random = require('./src/random');

module.exports = {
  ...encryption,
  ...hmac,
  ...keyManager,
  ...random,
};
