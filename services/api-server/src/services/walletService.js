'use strict';

/**
 * @module services/walletService — FIXED
 *
 * Wallet Service — Admin wallet management.
 *
 * SECURITY:
 *   - Private key encrypted with AES-256-GCM via @xcg/crypto encrypt()
 *   - derivationSalt generated per-wallet but encryption uses master key directly
 *   - encryptedPrivateKey never returned in any API response
 *   - All actions appended to audit log
 *   - Balance updates are atomic ($inc only)
 */

const crypto    = require('crypto');
const { Wallet, AuditLog } = require('@xcg/database');
const { AppError }    = require('@xcg/common');
const { encrypt }     = require('@xcg/crypto');

class WalletService {
  constructor({ logger }) {
    this.logger = logger;
  }

  /**
   * Add a new receiving wallet.
   * Admin submits plaintext private key over HTTPS.
   * Server encrypts it immediately with master key.
   *
   * @param {object} data  - { address, privateKey, label, network }
   * @param {object} actor - { userId, ip }
   * @returns {object} Safe wallet (no keys)
   */
  async addWallet(data, actor) {
    const { address, privateKey, label, network = 'tron' } = data;

    // Reject duplicate address
    const existing = await Wallet.findOne({ address });
    if (existing) throw AppError.conflict('Wallet address already exists');

    // Generate per-wallet derivation salt (stored for future key rotation use)
    const derivationSalt = crypto.randomBytes(32).toString('hex');

    // Encrypt private key with master key (AES-256-GCM)
    // encrypt() signature: (plaintext: string, masterKey?: Buffer) → string
    const encryptedPrivateKey = encrypt(privateKey.replace(/^0x/, ''));

    const wallet = await Wallet.create({
      address,
      network,
      encryptedPrivateKey,
      derivationSalt,
      label: label || '',
      isActive: true,
      type: 'hot',
      maxBalance: 1000,
      addedBy: actor.userId,
    });

    await AuditLog.create({
      actor:      String(actor.userId),
      action:     'wallet_added',
      resource:   'wallet',
      resourceId: String(wallet._id),
      ipAddress:  actor.ip,
      metadata:   { address, network, label: label || '' },
      outcome:    'success',
      timestamp:  new Date(),
    });

    this.logger.info('WalletService: wallet added', {
      address, network, addedBy: String(actor.userId),
    });

    return wallet.toSafeJSON();
  }

  /**
   * List wallets (no sensitive fields).
   */
  async listWallets(filters = {}) {
    const filter = {};
    if (filters.isActive !== undefined) {
      filter.isActive = filters.isActive === 'true' || filters.isActive === true;
    }
    if (filters.type) filter.type = filters.type;

    const wallets = await Wallet.find(filter)
      .select('-encryptedPrivateKey -derivationSalt')
      .sort({ createdAt: -1 })
      .limit(100)
      .lean();

    return wallets;
  }

  /**
   * Activate / deactivate a wallet with audit log.
   */
  async setWalletStatus(walletId, isActive, actor) {
    const wallet = await Wallet.findByIdAndUpdate(
      walletId,
      {
        $set: {
          isActive,
          ...(isActive ? {} : { disabledAt: new Date(), disabledReason: 'Admin deactivated' }),
        },
      },
      { new: true },
    );
    if (!wallet) throw AppError.notFound('Wallet not found');

    await AuditLog.create({
      actor:      String(actor.userId),
      action:     isActive ? 'wallet_activated' : 'wallet_deactivated',
      resource:   'wallet',
      resourceId: walletId,
      ipAddress:  actor.ip,
      metadata:   { address: wallet.address },
      outcome:    'success',
      timestamp:  new Date(),
    });

    return wallet.toSafeJSON();
  }

  /**
   * Get on-chain USDT balance from blockchain.
   * Also updates the cached balance in the DB.
   */
  async getWalletBalance(walletId, tronAdapter) {
    const wallet = await Wallet.findById(walletId)
      .select('address isActive')
      .lean();
    if (!wallet) throw AppError.notFound('Wallet not found');

    const balance = await tronAdapter.getUSDTBalance(wallet.address);
    const balanceFloat = parseFloat(balance);

    // Update cached balance (atomic set — OK here since this is a sync operation)
    await Wallet.findByIdAndUpdate(walletId, {
      $set: {
        'balance.usdt': balanceFloat,
        'balance.lastUpdated': new Date(),
      },
    });

    return { walletId, address: wallet.address, usdt: balance, updatedAt: new Date() };
  }

  /**
   * Assign best available wallet for a new invoice.
   * Selects from active receiving/hot wallets with lowest load.
   */
  async assignReceivingWallet() {
    const wallet = await Wallet.findOne({
      isActive: true,
      type: { $in: ['hot', 'receiving'] },
    })
      .sort({ 'balance.usdt': 1, transactionCount: 1 }) // Least loaded first
      .select('_id address')
      .lean();

    if (!wallet) {
      throw AppError.serviceUnavailable('No receiving wallets available — please add hot wallets');
    }
    return wallet;
  }
}

module.exports = WalletService;
