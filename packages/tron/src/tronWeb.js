'use strict';

/**
 * @module tronWeb
 *
 * Singleton TronWeb instance for the Signing Service.
 *
 * SECURITY:
 *   - Used ONLY by the Signing Service for transaction building/signing
 *   - Never used to read private keys — keys are managed by keyManager
 *   - Network configured from ENV (testnet/mainnet)
 *   - Private key NOT passed here — injected at signing time only
 */

const TronWeb = require('tronweb');

/**
 * Official TronGrid endpoints.
 * HARDCODED for security — never from user input.
 */
const TRON_ENDPOINTS = {
  mainnet: {
    fullHost: 'https://api.trongrid.io',
  },
  testnet: {
    fullHost: 'https://nile.trongrid.io',
  },
};

let _instance = null;

/**
 * Get the singleton TronWeb instance (no private key attached).
 * Private key is injected only at signing time in signing-service.
 *
 * @param {string} network - 'mainnet' | 'testnet'
 * @param {string} apiKey  - TronGrid API key
 * @returns {TronWeb}
 */
function getTronWeb(network, apiKey) {
  if (_instance) return _instance;

  if (!['mainnet', 'testnet'].includes(network)) {
    throw new Error(`getTronWeb: invalid network "${network}"`);
  }
  if (!apiKey) {
    throw new Error('getTronWeb: TRONGRID_API_KEY required');
  }

  const endpoint = TRON_ENDPOINTS[network];

  _instance = new TronWeb({
    fullHost: endpoint.fullHost,
    headers: { 'TRON-PRO-API-KEY': apiKey },
    // NOTE: No privateKey here — injected per-signing in signer.js
  });

  return _instance;
}

module.exports = { getTronWeb };
