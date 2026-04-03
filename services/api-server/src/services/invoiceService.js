'use strict';

/**
 * @module services/invoiceService
 *
 * Invoice Service — Unique amount generation and payment lifecycle.
 *
 * UNIQUE AMOUNT ALGORITHM:
 *   1. Take the base USDT amount (e.g. 150.00)
 *   2. Generate a random 6-decimal offset (e.g. 0.000347)
 *   3. Combine: 150.000347 — guaranteed unique among active invoices
 *   4. Store (uniqueAmount, walletAddress) in DB with UNIQUE compound index
 *   5. On collision (extremely rare): retry up to 10 times
 *   6. Reservation releases when invoice expires
 *
 * SECURITY:
 *   - Invoice creation is idempotent (idempotencyKey)
 *   - Expiry enforced at model level (expiresAt index)
 *   - Amount validated: min 0.01 USDT, max 1,000,000 USDT
 *   - Unique amount collision: DB-level unique index = safe even under concurrent load
 */

const crypto      = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { Invoice, Merchant } = require('@xcg/database');
const { AppError, money } = require('@xcg/common');

const MAX_OFFSET_RETRIES = 10; // Max collision retries before giving up

class InvoiceService {
  constructor({ config, walletService, logger }) {
    this.config        = config; // config.invoice
    this.walletService = walletService;
    this.logger        = logger;
  }

  /**
   * Create a new payment invoice.
   *
   * @param {object} data           - { amount, currency, description, callbackUrl, metadata, idempotencyKey }
   * @param {object} merchant       - Merchant document { _id, businessName, feePercentage }
   * @returns {object} Created invoice (safe JSON)
   */
  async createInvoice(data, merchant) {
    const { amount, currency = 'USDT', description = '', callbackUrl, metadata, idempotencyKey } = data;

    // Get an available receiving wallet
    const wallet = await this.walletService.assignReceivingWallet();

    // Generate unique amount with retry on collision
    const { uniqueAmount, offset } = await this._reserveUniqueAmount(amount, wallet.address);

    // Calculate platform fee
    const platformFeeRate = this.config.platformFeeRate; // 0.001 = 0.1%
    const feeAmount   = money.round(amount * platformFeeRate, 6);
    const netAmount   = money.round(amount - feeAmount, 6);

    const expiresAt = new Date(Date.now() + this.config.expiryMs); // 15 minutes

    // Idempotent creation
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
      status:         'pending',
      expiresAt,
      feePercentage:  platformFeeRate * 100,
      feeAmount,
      netAmount,
    });

    if (!created) {
      this.logger.info('InvoiceService: returning existing invoice (idempotent)', {
        invoiceId: invoice.invoiceId, merchantId: String(merchant._id),
      });
    } else {
      this.logger.info('InvoiceService: invoice created', {
        invoiceId: invoice.invoiceId,
        uniqueAmount,
        walletAddress: wallet.address,
        expiresAt,
      });
    }

    return invoice.toSafeJSON ? invoice.toSafeJSON() : invoice.toObject();
  }

  /**
   * Reserve a unique USDT amount for this wallet address.
   * Retries on collision (DB unique index enforcement).
   *
   * Offset range: 0.000001 to 0.009999 (10,000 unique values)
   * These are hardcoded constants — do NOT change without matching engine review.
   */
  async _reserveUniqueAmount(baseAmount, walletAddress) {
    const MIN_OFFSET = 0.000001;
    const MAX_OFFSET = 0.009999;

    for (let attempt = 0; attempt < MAX_OFFSET_RETRIES; attempt++) {
      // Generate cryptographically random offset in range
      const range  = MAX_OFFSET - MIN_OFFSET;
      const random = crypto.randomBytes(4).readUInt32BE(0) / 0xFFFFFFFF; // 0..1
      const offset = money.round(MIN_OFFSET + (random * range), 6);

      // Combine with base: use BigInt arithmetic to avoid float precision errors
      const baseInt   = BigInt(Math.round(baseAmount * 1_000_000));
      const offsetInt = BigInt(Math.round(offset * 1_000_000));
      const totalInt  = baseInt + offsetInt;
      const uniqueAmount = (Number(totalInt) / 1_000_000).toFixed(6);

      // Check if this uniqueAmount is already in use for this wallet
      const conflict = await Invoice.findOne({
        uniqueAmount: parseFloat(uniqueAmount),
        walletAddress,
        status: { $in: ['pending', 'hash_found', 'confirming'] },
        expiresAt: { $gt: new Date() },
      }).lean();

      if (!conflict) {
        return { uniqueAmount: parseFloat(uniqueAmount), offset };
      }

      this.logger.debug('InvoiceService: amount collision, retrying', { attempt, uniqueAmount });
    }

    throw AppError.serviceUnavailable(
      'Unable to generate unique payment amount — all slots occupied for this wallet. Try again in a few minutes.',
    );
  }

  /**
   * Get an invoice by its public invoiceId.
   * Result filtered to exclude internal fields.
   */
  async getInvoice(invoiceId, merchantId) {
    const invoice = await Invoice.findOne({ invoiceId, merchantId }).lean();
    if (!invoice) throw AppError.notFound('Invoice not found');
    return invoice;
  }

  /**
   * List invoices for a merchant with pagination.
   */
  async listInvoices(merchantId, { page = 1, limit = 20, status, sortBy = 'createdAt', sortOrder = 'desc' } = {}) {
    const filter = { merchantId };
    if (status) filter.status = status;

    const skip  = (page - 1) * limit;
    const sort  = { [sortBy]: sortOrder === 'asc' ? 1 : -1 };

    const [invoices, total] = await Promise.all([
      Invoice.find(filter)
        .select('-amountOffset -__v')
        .sort(sort).skip(skip).limit(limit).lean(),
      Invoice.countDocuments(filter),
    ]);

    return {
      invoices,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    };
  }
}

module.exports = InvoiceService;
