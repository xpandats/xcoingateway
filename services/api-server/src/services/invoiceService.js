'use strict';

/**
 * @module services/invoiceService — CORRECTED
 *
 * Fixes:
 *   - Uses INVOICE_STATUS constants (not string literals)
 *   - Correct walletId field (walletId vs walletAddress)
 *   - BigInt arithmetic preserved
 */

const crypto      = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { Invoice, WalletAssignment } = require('@xcg/database');
const { AppError, money } = require('@xcg/common');
const { INVOICE_STATUS } = require('@xcg/common').constants;
const { config }   = require('../config');
const cache        = require('../utils/cache');


const MAX_OFFSET_RETRIES = 10;

class InvoiceService {
  /**
   * @param {object} opts
   * @param {object} opts.walletService
   * @param {object} opts.logger
   * @param {object|null} [opts.redis=null] - IORedis client for slot cache
   */
  constructor({ walletService, logger, redis = null }) {
    this.walletService = walletService;
    this.logger        = logger;
    this.redis         = redis;
  }


  /**
   * Create a new payment invoice.
   */
  async createInvoice(data, merchant) {
    const {
      amount,
      currency = 'USDT',
      description = '',
      callbackUrl,
      metadata,
      idempotencyKey,
    } = data;

    // Assign the best available receiving wallet
    const wallet = await this.walletService.assignReceivingWallet();

    // Generate a unique amount for this invoice (avoids amount collision)
    const { uniqueAmount, offset } = await this._reserveUniqueAmount(amount, wallet.address);

    // Calculate platform fee
    const platformFeeRate = config.invoice.platformFeeRate;
    const feeAmount  = money.round(amount * platformFeeRate, 6);
    const netAmount  = money.round(amount - feeAmount, 6);
    const expiresAt  = new Date(Date.now() + config.invoice.expiryMs);

    const { invoice, created } = await Invoice.createIdempotent({
      invoiceId:      `inv_${uuidv4().replace(/-/g, '')}`,
      merchantId:     merchant._id,
      idempotencyKey: idempotencyKey || `inv:${uuidv4()}`,
      baseAmount:     amount,
      uniqueAmount,
      amountOffset:   offset,
      currency,
      network:        'tron',
      walletAddress:  wallet.address,
      walletId:       wallet._id,
      description,
      metadata:       metadata || {},
      callbackUrl:    callbackUrl || '',
      status:         INVOICE_STATUS.PENDING,   // ← FIXED: use constant not string literal
      expiresAt,
      feePercentage:  platformFeeRate * 100,
      feeAmount,
      netAmount,
    });

    if (!created) {
      this.logger.info('InvoiceService: returning idempotent invoice', {
        invoiceId: invoice.invoiceId,
      });
    } else {
      this.logger.info('InvoiceService: invoice created', {
        invoiceId:     invoice.invoiceId,
        uniqueAmount,
        walletAddress: wallet.address,
        expiresAt,
      });
    }

    // Track wallet assignment for load balancing metrics (non-blocking)
    if (created) {
      WalletAssignment.create({
        walletId:    wallet._id,
        invoiceId:   invoice._id,
        merchantId:  merchant._id,
        network:     'tron',
        assignedAt:  new Date(),
        expiresAt:   expiresAt,
        status:      'active',
        selectionReason: 'round_robin',
      }).catch((e) => this.logger.debug('InvoiceService: WalletAssignment write failed', { error: e.message }));
    }

    return invoice.toSafeJSON ? invoice.toSafeJSON() : invoice.toObject();
  }

  /**
   * Reserve a unique USDT amount via crypto-random offset.
   *
   * Two-layer collision prevention (Gap 2 fix):
   *   Layer 1 — Redis slot cache: Redis NX check is O(1) and avoids a DB query
   *     entirely for already-occupied slots. Under load (burst of invoice creation
   *     for the same wallet) this eliminates most MongoDB collision queries.
   *   Layer 2 — MongoDB: authoritative source. Always checked after Redis says free,
   *     because Redis has a TTL and could miss a slot reserved before Redis was added.
   *
   * On Redis failure: falls through to MongoDB-only mode (fail-open).
   */
  async _reserveUniqueAmount(baseAmount, walletAddress) {
    const MIN_OFFSET  = 0.000001;
    const MAX_OFFSET  = 0.009999;
    // INVOICE_SLOT TTL: slightly longer than invoice expiry to cover edge cases
    const slotTtl = Math.ceil((config.invoice.expiryMs || 1_200_000) / 1000) + 120;

    for (let attempt = 0; attempt < MAX_OFFSET_RETRIES; attempt++) {
      const range  = MAX_OFFSET - MIN_OFFSET;
      const random = crypto.randomBytes(4).readUInt32BE(0) / 0xFFFFFFFF;
      const offset = money.round(MIN_OFFSET + (random * range), 6);

      const baseInt    = BigInt(Math.round(baseAmount * 1_000_000));
      const offsetInt  = BigInt(Math.round(offset * 1_000_000));
      const totalInt   = baseInt + offsetInt;
      const uniqueAmount = Number(totalInt) / 1_000_000;

      // Layer 1: Redis slot check (fast, no DB touch)
      const redisSlotFree = await cache.reserveInvoiceSlot(
        this.redis,
        walletAddress,
        uniqueAmount,
        slotTtl,
      );

      if (!redisSlotFree) {
        // Slot is already reserved in Redis — skip without DB query
        this.logger.debug('InvoiceService: slot occupied in Redis cache, retrying', {
          attempt, uniqueAmount,
        });
        continue;
      }

      // Layer 2: MongoDB authoritative check
      const conflict = await Invoice.findOne({
        uniqueAmount,
        walletAddress,
        status:    { $in: [INVOICE_STATUS.PENDING, INVOICE_STATUS.HASH_FOUND, INVOICE_STATUS.CONFIRMING] },
        expiresAt: { $gt: new Date() },
      }).select('_id').lean();

      if (!conflict) {
        // Both Redis and DB say free — slot is ours
        return { uniqueAmount, offset };
      }

      // DB found a conflict that Redis didn't know about — release our Redis reservation
      // and try again. (This happens when invoice was created before Redis cache was added.)
      await cache.releaseInvoiceSlot(this.redis, walletAddress, uniqueAmount);
      this.logger.debug('InvoiceService: DB conflict found, cleared Redis reservation, retrying', {
        attempt, uniqueAmount,
      });
    }

    throw AppError.serviceUnavailable(
      'Unable to generate unique payment amount — all slots occupied. Please retry in a few minutes.',
    );
  }

  /**
   * Get invoice by public invoiceId (merchant-scoped).
   */
  async getInvoice(invoiceId, merchantId) {
    const invoice = await Invoice.findOne({ invoiceId, merchantId })
      .select('-amountOffset -__v')
      .lean();
    if (!invoice) throw AppError.notFound('Invoice not found');
    return invoice;
  }

  /**
   * List invoices for a merchant with pagination.
   */
  async listInvoices(merchantId, { page = 1, limit = 20, status } = {}) {
    const filter = { merchantId };
    if (status) filter.status = status;

    const skip = (page - 1) * limit;
    const [invoices, total] = await Promise.all([
      Invoice.find(filter)
        .select('-amountOffset -__v')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      Invoice.countDocuments(filter),
    ]);

    return {
      invoices,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    };
  }
}

module.exports = InvoiceService;
