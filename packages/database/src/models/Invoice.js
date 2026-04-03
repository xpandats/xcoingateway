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
  baseAmount: { type: Number, required: true }, // Original amount requested (e.g., 150.00)
  uniqueAmount: { type: Number, required: true, index: true }, // With offset (e.g., 150.000347)
  amountOffset: { type: Number, required: true }, // The unique offset applied
  currency: { type: String, default: 'USDT' },
  network: { type: String, default: 'tron' },

  // Payment details
  walletAddress: { type: String, required: true, index: true }, // Receiving wallet
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

// Compound indexes for matching engine
invoiceSchema.index({ uniqueAmount: 1, walletAddress: 1, status: 1 });
invoiceSchema.index({ status: 1, expiresAt: 1 }); // For expiry scanning
invoiceSchema.index({ merchantId: 1, createdAt: -1 }); // For merchant dashboard

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
