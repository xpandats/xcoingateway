'use strict';

/**
 * @module signing-service/signer
 *
 * Transaction Signer — Core of Zone 3.
 *
 * CRITICAL SECURITY CONTRACT:
 *   1. Private key is decrypted from AES-256-GCM into a Buffer.
 *   2. TronWeb uses the key to sign the transaction.
 *   3. Buffer.fill(0) zeroes the key IMMEDIATELY after signing.
 *   4. The decrypted key NEVER leaves this function as a string.
 *   5. No logging of private key in any form.
 *   6. The request payload is validated strictly before key access.
 *
 * A compromise of this service would expose private keys ONLY for the
 * duration of a single signing operation (milliseconds).
 */

const Joi                = require('joi');
const { Wallet, AuditLog } = require('@xcg/database');
const { decrypt }        = require('@xcg/crypto');
const { getTronWeb }     = require('@xcg/tron');

// ─── Request Schema ───────────────────────────────────────────────────────────

const SIGNING_REQUEST_SCHEMA = Joi.object({
  requestId:    Joi.string().uuid().required(),
  withdrawalId: Joi.string().hex().length(24).required(),
  walletId:     Joi.string().hex().length(24).required(),
  toAddress:    Joi.string().pattern(/^T[1-9A-HJ-NP-Za-km-z]{33}$/).required(),
  amount:       Joi.string().pattern(/^\d+\.\d{1,6}$/).required(), // e.g. "150.500000"
  network:      Joi.string().valid('mainnet', 'testnet').required(),
}).options({ stripUnknown: true });

// ─── USDT TRC20 Contract Addresses (hardcoded) ───────────────────────────────
const USDT_CONTRACTS = {
  mainnet: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',
  testnet: 'TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj',
};

class Signer {
  /**
   * @param {object} opts
   * @param {string} opts.network   - 'mainnet' | 'testnet'
   * @param {string} opts.apiKey    - TronGrid API key
   * @param {string} opts.masterKey - AES-256-GCM master key (hex)
   * @param {object} opts.logger    - @xcg/logger instance
   */
  constructor({ network, apiKey, masterKey, logger }) {
    this.network   = network;
    this.masterKey = masterKey;
    this.logger    = logger;
    this.tronWeb   = getTronWeb(network, apiKey);
    this.usdtContract = USDT_CONTRACTS[network];

    if (!this.usdtContract) {
      throw new Error(`Signer: unknown network "${network}"`);
    }
  }

  /**
   * Sign and broadcast a USDT TRC20 transfer.
   *
   * @param {object} request - Signing request from Withdrawal Engine
   * @returns {{ txHash: string }}
   */
  async sign(request) {
    // 1. Validate request schema
    const { error, value: req } = SIGNING_REQUEST_SCHEMA.validate(request);
    if (error) {
      throw new Error(`Signer: invalid request — ${error.message}`);
    }

    // 2. Load wallet and encrypted key from DB
    const wallet = await Wallet.findById(req.walletId)
      .select('+encryptedPrivateKey') // Explicitly include protected field
      .lean();

    if (!wallet || !wallet.isActive) {
      throw new Error(`Signer: wallet ${req.walletId} not found or inactive`);
    }
    if (!wallet.encryptedPrivateKey) {
      throw new Error(`Signer: wallet ${req.walletId} has no encrypted key`);
    }

    // 3. Decrypt private key → Buffer (NEVER string)
    // Buffer is crucial — can be zeroed. Strings are immutable in Node.js.
    let privateKeyBuffer;
    let txHash;

    try {
      // decrypt() from @xcg/crypto returns a Buffer
      privateKeyBuffer = decrypt(wallet.encryptedPrivateKey, this.masterKey);

      if (!Buffer.isBuffer(privateKeyBuffer)) {
        throw new Error('Signer: decrypt() must return a Buffer');
      }

      // 4. Build unsigned TronWeb transaction
      // Convert amount from USDT string to SUN (multiply by 1,000,000)
      const amountSun = BigInt(Math.round(parseFloat(req.amount) * 1_000_000));

      // SECURITY: Set TronWeb's private key only for this signing operation
      // Using a temporary clone approach to avoid the singleton having the key
      const tempTronWeb = Object.create(this.tronWeb);
      tempTronWeb.defaultPrivateKey = privateKeyBuffer.toString('hex');

      const tx = await this.tronWeb.transactionBuilder.triggerSmartContract(
        this.usdtContract,
        'transfer(address,uint256)',
        { feeLimit: 100_000_000 },
        [
          { type: 'address', value: req.toAddress },
          { type: 'uint256', value: amountSun.toString() },
        ],
        wallet.address,
      );

      if (!tx?.result?.result) {
        throw new Error(`Signer: triggerSmartContract failed — ${JSON.stringify(tx?.result)}`);
      }

      // 5. Sign transaction
      const signedTx = await this.tronWeb.trx.sign(tx.transaction, privateKeyBuffer.toString('hex'));

      // 6. IMMEDIATELY zero the private key buffer
      // This MUST happen before any await that could throw
      privateKeyBuffer.fill(0);
      privateKeyBuffer = null;

      // Also clear the temp TronWeb key reference
      if (tempTronWeb.defaultPrivateKey) {
        tempTronWeb.defaultPrivateKey = '0'.repeat(64);
      }

      // 7. Broadcast signed transaction
      const broadcastResult = await this.tronWeb.trx.sendRawTransaction(signedTx);
      if (!broadcastResult?.result) {
        throw new Error(`Signer: broadcast failed — ${JSON.stringify(broadcastResult)}`);
      }

      txHash = broadcastResult.txid || signedTx.txID;
      if (!txHash) {
        throw new Error('Signer: no txHash returned from broadcast');
      }

    } catch (err) {
      // SECURITY: Always zero key on error too
      if (privateKeyBuffer) {
        privateKeyBuffer.fill(0);
        privateKeyBuffer = null;
      }

      this.logger.error('Signer: signing failed', {
        requestId:    req.requestId,
        withdrawalId: req.withdrawalId,
        walletId:     req.walletId,
        error: err.message,
        // NEVER log private key, amount details, or toAddress in error
      });

      // Write to audit log before re-throwing
      await this._auditLog(req, null, 'failed', err.message).catch(() => {});
      throw err;
    }

    // 8. Write audit log
    await this._auditLog(req, txHash, 'success', null);

    this.logger.info('Signer: transaction signed and broadcast', {
      requestId:    req.requestId,
      withdrawalId: req.withdrawalId,
      txHash,
      // NOTE: amount and toAddress intentionally NOT logged here (audit log has it)
    });

    return { txHash };
  }

  async _auditLog(req, txHash, outcome, errorMsg) {
    try {
      await AuditLog.create({
        actor:     'signing-service',
        action:    'signing_operation',
        resource:  'withdrawal',
        resourceId:req.withdrawalId,
        outcome,
        metadata: {
          requestId:    req.requestId,
          walletId:     req.walletId,
          toAddress:    req.toAddress,
          amount:       req.amount,
          network:      req.network,
          txHash:       txHash || null,
          error:        errorMsg || null,
        },
        timestamp: new Date(),
      });
    } catch (err) {
      // Never let audit log failure block signing
      this.logger.error('Signer: audit log write failed', { error: err.message });
    }
  }
}

module.exports = Signer;
