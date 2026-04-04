'use strict';

/**
 * @module models/Invoice
 *
 * Invoice — Payment request from a merchant.
 * Contains the unique decimal amount used for blockchain matching.
 */

const mongoose = require('mongoose');
const { INVOICE_STATUS } = require('@xcg/common').constants;

const invoiceSchema = new mongoose.Schema({
  // Identifiers
  invoiceId: { type: String, required: true, unique: true }, // Public-facing ID (inv_xxx)
  merchantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant', required: true, index: true },
  idempotencyKey: { type: String, sparse: true, unique: true }, // Prevents duplicate creation

  // Amount
  baseAmount: { type: Number, required: true, min: 0.01 },     // BL-4: no negative/zero
  uniqueAmount: { type: Number, required: true, index: true, min: 0.01 }, // BL-4
  amountOffset: { type: Number, required: true },
  currency: { type: String, default: 'USDT' },
  network: { type: String, default: 'tron' },

  // Payment details
  walletAddress: { type: String, required: true, index: true }, // Receiving wallet TRC20 address
  walletId:      { type: mongoose.Schema.Types.ObjectId, ref: 'Wallet', default: null, index: true }, // Wallet ref for reconciliation
  description: { type: String, default: '' },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }, // Merchant custom data

  // Status
  status: {
    type: String,
    enum: Object.values(INVOICE_STATUS),
    default: INVOICE_STATUS.INITIATED,
    index: true,
  },

  // Timing
  expiresAt: { type: Date, required: true, index: true },
  paidAt: { type: Date, default: null },
  confirmedAt: { type: Date, default: null },

  // Linked transaction (after match)
  transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction', default: null },
  txHash: { type: String, default: null },

  // Webhook
  callbackUrl: { type: String, default: '' },
  webhookSent: { type: Boolean, default: false },

  // Fee calculation
  feePercentage: { type: Number, default: 0 },
  fixedFee: { type: Number, default: 0 },
  feeAmount: { type: Number, default: 0 },
  netAmount: { type: Number, default: 0 }, // Amount merchant receives after fees
}, {
  timestamps: true,
  collection: 'invoices',
  strict: true, // L4: explicit — reject unknown fields at DB write level
});

// BL-3: Compound unique index — prevents two invoices on the same wallet
// getting identical uniqueAmount, which would cause the matching engine to
// match the wrong invoice (race condition in unique amount generation).
invoiceSchema.index({ uniqueAmount: 1, walletAddress: 1 }, { unique: true });
invoiceSchema.index({ status: 1, expiresAt: 1 }); // For expiry scanning
invoiceSchema.index({ merchantId: 1, createdAt: -1 }); // For merchant dashboard

// G9 FIX: Enforce metadata size limit — prevents BSON document bloat injection
// A malicious or poorly-coded merchant SDK could send 16MB metadata per invoice
invoiceSchema.pre('save', function (next) {
  if (this.metadata && typeof this.metadata === 'object') {
    try {
      const size = Buffer.byteLength(JSON.stringify(this.metadata), 'utf8');
      if (size > 4096) {
        return next(new Error(`Invoice metadata exceeds 4KB limit (${size} bytes). Store large data in your own system.`));
      }
    } catch {
      return next(new Error('Invoice metadata must be a JSON-serializable object.'));
    }
  }
  next();
});

// Safe for external API — excludes internal fee breakdown
invoiceSchema.methods.toSafeJSON = function () {
  const obj = this.toObject();
  delete obj.__v;
  delete obj.amountOffset; // Internal implementation detail
  return obj;
};

/**
 * K1: Idempotent invoice creation.
 * If a duplicate idempotencyKey is used, returns the EXISTING invoice
 * instead of throwing a MongoServerError 11000.
 *
 * USAGE (in invoice service):
 *   const { invoice, created } = await Invoice.createIdempotent(data);
 *
 * @param {object} data - Invoice fields
 * @returns {{ invoice: Document, created: boolean }}
 */
invoiceSchema.statics.createIdempotent = async function (data) {
  try {
    const invoice = await this.create(data);
    return { invoice, created: true };
  } catch (err) {
    // 11000 = MongoDB duplicate key — idempotencyKey already exists
    if (err.code === 11000 && data.idempotencyKey) {
      const existing = await this.findOne({ idempotencyKey: data.idempotencyKey });
      if (existing) return { invoice: existing, created: false };
    }
    throw err; // Re-throw all other errors
  }
};

module.exports = mongoose.model('Invoice', invoiceSchema);
