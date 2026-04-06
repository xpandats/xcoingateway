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
const cache           = require('../utils/cache');


class WalletService {
  /**
   * @param {object} opts
   * @param {object} opts.logger
   * @param {object|null} [opts.redis=null] - IORedis client for cache invalidation
   */
  constructor({ logger, redis = null }) {
    this.logger = logger;
    this.redis  = redis;
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

    // Invalidate active wallet list cache — new wallet must be visible to listener/engine
    await cache.invalidateWallets(this.redis);

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

    // Invalidate active wallet list — deactivated wallet must stop receiving payments
    // immediately. A stale cache entry here would cause the listener to still route
    // incoming transfers to a disabled wallet.
    await cache.invalidateWallets(this.redis);

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

    // Update cached balance (atomic set)
    await Wallet.findByIdAndUpdate(walletId, {
      $set: {
        'balance.usdt': balanceFloat,
        'balance.lastUpdated': new Date(),
      },
    });

    // Balance changed — invalidate wallet list cache so processor picks up fresh balance
    await cache.invalidateWallets(this.redis);

    return { walletId, address: wallet.address, usdt: balance, updatedAt: new Date() };
  }


  /**
   * Assign best available wallet for a new invoice.
   * Uses Redis cache (Gap 1 fix) with stampede protection.
   */
  async assignReceivingWallet() {
    const wallets = await cache.getActiveWallets(
      this.redis,
      async () => Wallet.find({
        isActive: true,
        type: { $in: ['hot', 'receiving'] },
      })
        .select('_id address balance transactionCount')
        .lean(),
    );

    if (!wallets || wallets.length === 0) {
      throw AppError.serviceUnavailable('No receiving wallets available — please add hot wallets');
    }

    // Select least-loaded wallet in-process (lowest balance + lowest txCount)
    const wallet = wallets
      .filter((w) => w._id && w.address)
      .sort((a, b) => {
        const balDiff = parseFloat(a.balance?.usdt || 0) - parseFloat(b.balance?.usdt || 0);
        if (balDiff !== 0) return balDiff;
        return (a.transactionCount || 0) - (b.transactionCount || 0);
      })[0];

    if (!wallet) {
      throw AppError.serviceUnavailable('No valid receiving wallets available');
    }
    return wallet;
  }
}

module.exports = WalletService;
