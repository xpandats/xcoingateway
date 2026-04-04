'use strict';

/**
 * @module adapters/tron
 *
 * Tron Blockchain Adapter — USDT TRC20 Implementation.
 *
 * Supports:
 *   - Testnet: Nile (https://nile.trongrid.io)
 *   - Mainnet: TronGrid (https://api.trongrid.io)
 *
 * Primary provider: TronGrid (free tier, requires API key)
 * Fallback provider: Public Tron RPC node
 *
 * SECURITY:
 *   - USDT_TRC20_CONTRACT is HARDCODED — never from user input or env
 *   - All external responses are validated before use
 *   - Timeouts enforced on every outbound request (10s)
 *   - Provider rotation on failure
 */

const axios = require('axios');
const BlockchainAdapter = require('./base');

// ─── CONSTANTS (NEVER from env — hardcoded for security) ─────────────────────

/**
 * Official USDT TRC20 contract addresses.
 * Source: https://tronscan.org/#/token20/TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t
 * DO NOT CHANGE without formal security review.
 */
const USDT_CONTRACTS = {
  mainnet: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',
  testnet: 'TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj', // Nile testnet USDT
};

const TRON_PROVIDERS = {
  mainnet: {
    primary: 'https://api.trongrid.io',
    fallback: 'https://api.tronstack.io',
  },
  testnet: {
    primary: 'https://nile.trongrid.io',
    fallback: 'https://nile.tronstack.io',
  },
};

const REQUEST_TIMEOUT_MS = 10_000; // 10 seconds — never wait forever on external APIs

class TronAdapter extends BlockchainAdapter {
  /**
   * @param {object} config
   * @param {string} config.network - 'mainnet' | 'testnet'
   * @param {string} config.apiKey  - TronGrid API key (from ENV)
   * @param {object} logger         - @xcg/logger instance
   */
  constructor(config, logger) {
    super('tron', config);

    if (!config.apiKey) {
      throw new Error('TronAdapter: TRONGRID_API_KEY is required');
    }
    if (!['mainnet', 'testnet'].includes(config.network)) {
      throw new Error(`TronAdapter: invalid network "${config.network}"`);
    }

    this.network = config.network;
    this.usdtContract = USDT_CONTRACTS[config.network];
    this.primaryUrl = TRON_PROVIDERS[config.network].primary;
    this.fallbackUrl = TRON_PROVIDERS[config.network].fallback;
    this.apiKey = config.apiKey;
    this.logger = logger;
    this._usingFallback = false;
  }

  // ─── HTTP Client ────────────────────────────────────────────────────────────

  /**
   * Make an authenticated request to TronGrid.
   * Automatically falls back to public RPC on failure.
   * @param {string} path
   * @param {object} [body]
   * @param {string} [method='GET']
   */
  async _request(path, body = null, method = 'GET') {
    const baseUrl = this._usingFallback ? this.fallbackUrl : this.primaryUrl;
    const url = `${baseUrl}${path}`;

    try {
      const options = {
        method,
        url,
        timeout: REQUEST_TIMEOUT_MS,
        headers: {
          'TRON-PRO-API-KEY': this.apiKey,
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
      };
      if (body) options.data = body;

      const resp = await axios(options);

      // Reset to primary on success after fallback
      if (this._usingFallback) {
        this._usingFallback = false;
        this.logger.info('TronAdapter: reverted to primary provider');
      }

      return resp.data;
    } catch (err) {
      if (!this._usingFallback) {
        this.logger.warn('TronAdapter: primary provider failed, switching to fallback', {
          error: err.message,
          url,
        });
        this._usingFallback = true;
        // Retry with fallback
        return this._request(path, body, method);
      }
      // Both providers failed
      this.logger.error('TronAdapter: ALL providers failed', { path, error: err.message });
      throw new Error(`TronAdapter: blockchain unavailable — ${err.message}`);
    }
  }

  // ─── Interface Implementation ────────────────────────────────────────────────

  async getLatestBlock() {
    const data = await this._request('/wallet/getnowblock');
    const blockNum = data?.block_header?.raw_data?.number;
    if (typeof blockNum !== 'number') {
      throw new Error('TronAdapter: invalid block response — missing block number');
    }
    return blockNum;
  }

  async getTransfersInBlock(blockNum) {
    if (typeof blockNum !== 'number' || blockNum < 0) {
      throw new Error('TronAdapter: invalid blockNum');
    }

    // TronGrid: get all TRC20 transfers in block
    const data = await this._request(
      `/v1/blocks/${blockNum}/events?event_name=Transfer&contract_address=${this.usdtContract}&limit=200`,
    );

    if (!Array.isArray(data?.data)) {
      return []; // Empty block or no USDT transfers
    }

    const transfers = [];
    for (const event of data.data) {
      try {
        const parsed = this._parseTransferEvent(event, blockNum);
        if (parsed) transfers.push(parsed);
      } catch (err) {
        // Log and skip malformed events — never crash on bad blockchain data
        this.logger.warn('TronAdapter: skipping malformed transfer event', {
          error: err.message,
          txHash: event?.transaction_id,
        });
      }
    }
    return transfers;
  }

  /**
   * Parse and validate a TronGrid Transfer event.
   * Returns null if event is malformed or not USDT.
   * SECURITY: Validates contract address explicitly — never trust event type alone.
   */
  _parseTransferEvent(event, blockNum) {
    // Required fields
    const txHash = event?.transaction_id;
    const contract = event?.contract_address;
    const from = event?.result?.from;
    const to = event?.result?.to;
    const value = event?.result?.value;
    const ts = event?.block_timestamp;

    if (!txHash || !contract || !from || !to || !value || !ts) {
      return null;
    }

    // SECURITY: Hard-validate contract address — reject any event not from
    // the official USDT TRC20 contract. Protects against fake token attacks.
    if (contract.toLowerCase() !== this.usdtContract.toLowerCase()) {
      return null;
    }

    // Convert sun (6 decimals) to USDT string
    // USDT TRC20 uses 6 decimal places: 1 USDT = 1,000,000 sun
    const amountSun = BigInt(value);
    const amountStr = this._sunToUsdt(amountSun);

    return {
      txHash,
      blockNum,
      fromAddress: this._normalizeAddress(from),
      toAddress: this._normalizeAddress(to),
      amount: amountStr,                 // Human-readable (e.g. "150.000347")
      amountRaw: value,                  // Original sun value string
      tokenContract: contract,
      tokenSymbol: 'USDT',
      network: this.network,
      timestamp: Math.floor(ts / 1000), // Convert ms to seconds
    };
  }

  /**
   * Convert sun (integer, 6 decimals) to USDT string with 6dp precision.
   * Uses BigInt to avoid float imprecision.
   */
  _sunToUsdt(amountSun) {
    const SUN_PER_USDT = 1_000_000n;
    const intPart = amountSun / SUN_PER_USDT;
    const fracPart = amountSun % SUN_PER_USDT;
    const fracStr = fracPart.toString().padStart(6, '0');
    return `${intPart}.${fracStr}`;
  }

  /**
   * Normalize Tron address format (handle hex vs base58).
   */
  _normalizeAddress(addr) {
    // TronGrid returns hex addresses starting with 41...
    // Return as-is for now; TronWeb handles conversion during signing
    return addr;
  }

  async getConfirmations(txHash) {
    if (!txHash || typeof txHash !== 'string') {
      throw new Error('TronAdapter: invalid txHash');
    }
    const [latest, txInfo] = await Promise.all([
      this.getLatestBlock(),
      this._getTxBlockNum(txHash),
    ]);
    if (txInfo === null) return 0; // TX not found yet
    return Math.max(0, latest - txInfo);
  }

  async _getTxBlockNum(txHash) {
    try {
      const data = await this._request('/wallet/gettransactioninfobyid', { value: txHash }, 'POST');
      return typeof data?.blockNumber === 'number' ? data.blockNumber : null;
    } catch {
      return null;
    }
  }

  async getUSDTBalance(address) {
    if (!this.isValidAddress(address)) {
      throw new Error(`TronAdapter: invalid address "${address}"`);
    }
    // Query TRC20 balance
    const data = await this._request(
      `/v1/accounts/${address}/tokens?token_id=${this.usdtContract}&limit=1`,
    );
    const tokens = data?.data;
    if (!Array.isArray(tokens) || tokens.length === 0) return '0.000000';
    const balanceSun = BigInt(tokens[0]?.balance || '0');
    return this._sunToUsdt(balanceSun);
  }

  async broadcastTransaction(signedTx) {
    if (!signedTx || typeof signedTx !== 'object') {
      throw new Error('TronAdapter: invalid signed transaction');
    }
    const data = await this._request('/wallet/broadcasttransaction', signedTx, 'POST');
    if (!data?.result) {
      throw new Error(`TronAdapter: broadcast failed — ${JSON.stringify(data)}`);
    }
    const txHash = data?.txid || signedTx?.txID;
    if (!txHash) {
      throw new Error('TronAdapter: no txHash returned from broadcast');
    }
    return { txHash };
  }

  isValidAddress(address) {
    if (typeof address !== 'string') return false;
    // Tron base58check addresses start with 'T' and are 34 chars
    return /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(address);
  }

  getUSDTContractAddress() {
    return this.usdtContract;
  }

  /**
   * Get wallet energy balance from TronGrid.
   * Energy is required for TRC20 transfers — without it, TRX is burned as fee.
   *
   * @param {string} address - Tron wallet address
   * @returns {Promise<{ energy: number, energyLimit: number, bandwidth: number }>}
   */
  async getEnergyBalance(address) {
    try {
      const url = `${this.baseUrl}/v1/accounts/${address}`;
      const resp = await axios.get(url, {
        headers:    this._buildHeaders(),
        timeout:    REQUEST_TIMEOUT_MS,
        validateStatus: (s) => s === 200,
      });

      const data = resp.data?.data?.[0];
      if (!data) return { energy: 0, energyLimit: 0, bandwidth: 0 };

      // TronGrid returns energy in account resource
      const energy      = data.account_resource?.energy_usage_total || 0;
      const energyLimit = data.account_resource?.EnergyLimit || 0;
      const bandwidth   = data.free_net_usage || 0;
      const remainingEnergy = Math.max(0, energyLimit - energy);

      return { energy: remainingEnergy, energyLimit, bandwidth };
    } catch (err) {
      this.logger.warn('TronAdapter: failed to get energy balance', {
        address, error: err.message,
      });
      // Fail safe: return 0 — caller will queue withdrawal pending energy check
      return { energy: 0, energyLimit: 0, bandwidth: 0 };
    }
  }

  /**
   * Check if wallet has enough energy for a USDT TRC20 transfer.
   * USDT TRC20 requires ~65,000 energy per transfer.
   *
   * @param {string} address - Tron wallet address
   * @returns {Promise<boolean>}
   */
  async hasSufficientEnergy(address) {
    const ENERGY_PER_TRC20_TRANSFER = 65_000; // From TRON constants
    const { energy } = await this.getEnergyBalance(address);
    return energy >= ENERGY_PER_TRC20_TRANSFER;
  }
}

module.exports = TronAdapter;
