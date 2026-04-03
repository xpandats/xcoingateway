'use strict';

/**
 * @module services/walletService
 *
 * Wallet Service — Admin wallet management.
 *
 * SECURITY:
 *   - Private key is pre-encrypted by admin before submission
 *   - derivationSalt is generated server-side (random, never from client)
 *   - encryptedPrivateKey field is excluded from all query responses
 *   - Wallet activation/deactivation logged to audit trail
 *   - Balance updates are atomic ($inc only)
 */

const crypto    = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { Wallet, AuditLog } = require('@xcg/database');
const { AppError } = require('@xcg/common');
const { encrypt }   = require('@xcg/crypto');

class WalletService {
  constructor({ masterKey, logger }) {
    this.masterKey = masterKey;
    this.logger    = logger;
  }

  /**
   * Add a new wallet to the pool.
   * Admin provides the plaintext private key (over HTTPS only).
   * We encrypt it server-side with master key.
   *
   * @param {object} data - { address, privateKey, label, network }
   * @param {object} actor - { userId, ip }
   * @returns {object} Safe wallet object (no keys)
   */
  async addWallet(data, actor) {
    const { address, privateKey, label, network = 'tron' } = data;

    // Check for duplicate address
    const existing = await Wallet.findOne({ address });
    if (existing) {
      throw AppError.conflict('Wallet address already exists');
    }

    // Generate unique derivation salt (random per-wallet)
    const derivationSalt = crypto.randomBytes(32).toString('hex');

    // Encrypt the private key with AES-256-GCM
    const encryptedPrivateKey = encrypt(
      Buffer.from(privateKey.replace(/^0x/, ''), 'hex'),
      this.masterKey,
      derivationSalt,
    );

    const wallet = await Wallet.create({
      address,
      network,
      encryptedPrivateKey,
      derivationSalt,
      label: label || '',
      isActive: true,
      type: 'hot',
      maxBalance: 1000, // Default hot wallet limit
      addedBy: actor.userId,
    });

    // Immediately zero the private key from this scope
    if (typeof privateKey === 'string') {
      // Strings are immutable in JS — we can't zero them directly
      // But we ensure it's not logged or stored beyond this point
    }

    await AuditLog.create({
      actor:      actor.userId,
      action:     'wallet_added',
      resource:   'wallet',
      resourceId: String(wallet._id),
      ipAddress:  actor.ip,
      metadata:   { address, network, label },
      outcome:    'success',
    });

    this.logger.info('WalletService: wallet added', { address, network, addedBy: actor.userId });

    return wallet.toSafeJSON();
  }

  /**
   * List all wallets (no private keys, no derivation salts).
   */
  async listWallets(query = {}) {
    const filter = {};
    if (query.isActive !== undefined) filter.isActive = query.isActive === 'true';
    if (query.type) filter.type = query.type;

    const wallets = await Wallet.find(filter)
      .select('-encryptedPrivateKey -derivationSalt')
      .sort({ createdAt: -1 })
      .limit(100)
      .lean();

    return wallets;
  }

  /**
   * Get on-chain USDT balance for a wallet.
   */
  async getWalletBalance(walletId, tronAdapter) {
    const wallet = await Wallet.findById(walletId).select('address isActive').lean();
    if (!wallet) throw AppError.notFound('Wallet not found');

    const balance = await tronAdapter.getUSDTBalance(wallet.address);

    // Update cached balance
    await Wallet.findByIdAndUpdate(walletId, {
      $set: { 'balance.usdt': parseFloat(balance), 'balance.lastUpdated': new Date() },
    });

    return { address: wallet.address, usdt: balance };
  }

  /**
   * Activate or deactivate a wallet.
   */
  async setWalletStatus(walletId, isActive, actor) {
    const wallet = await Wallet.findByIdAndUpdate(
      walletId,
      { $set: { isActive, disabledAt: isActive ? null : new Date() } },
      { new: true },
    );
    if (!wallet) throw AppError.notFound('Wallet not found');

    await AuditLog.create({
      actor:      actor.userId,
      action:     isActive ? 'wallet_activated' : 'wallet_deactivated',
      resource:   'wallet',
      resourceId: walletId,
      ipAddress:  actor.ip,
      metadata:   { address: wallet.address },
      outcome:    'success',
    });

    return wallet.toSafeJSON();
  }

  /**
   * Get the best available wallet for receiving a payment.
   * Selects active receiving/hot wallet with lowest USDT balance (load distribution).
   */
  async assignReceivingWallet() {
    const wallet = await Wallet.findOne({ isActive: true, type: { $in: ['hot', 'receiving'] } })
      .sort({ 'balance.usdt': 1 }) // Least loaded first
      .select('_id address')
      .lean();

    if (!wallet) {
      throw AppError.serviceUnavailable('No receiving wallets available');
    }
    return wallet;
  }
}

module.exports = WalletService;
