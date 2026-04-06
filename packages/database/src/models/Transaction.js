'use strict';

/**
 * @module models/Transaction
 *
 * Blockchain Transaction — detected incoming transfers.
 * Immutable after matching (status updates only via service layer).
 */

const mongoose = require('mongoose');
const { TX_STATUS } = require('@xcg/common').constants;

const transactionSchema = new mongoose.Schema({
  // Blockchain data
  txHash: { type: String, required: true, unique: true },
  network: { type: String, required: true, default: 'tron' },
  blockNumber: { type: Number, required: true, index: true },
  blockTimestamp: { type: Date, required: true },

  // Transfer details
  fromAddress: { type: String, required: true, index: true },
  toAddress: { type: String, required: true, index: true },
  amount: { type: Number, required: true },
  tokenContract: { type: String, required: true }, // USDT contract address
  tokenSymbol: { type: String, default: 'USDT' },

  // Matching
  status: {
    type: String,
    enum: Object.values(TX_STATUS),
    default: TX_STATUS.DETECTED,
    index: true,
  },
  matchedInvoiceId: { type: mongoose.Schema.Types.ObjectId, ref: 'Invoice', default: null, index: true },
  matchedAt: { type: Date, default: null },
  matchResult: { type: String, default: null }, // Reason for match/no-match

  // Confirmations
  confirmations: { type: Number, default: 0 },
  requiredConfirmations: { type: Number, default: 19 },
  confirmedAt: { type: Date, default: null },

  // Processing
  detectedAt: { type: Date, default: Date.now },
  processedAt: { type: Date, default: null },
  processingAttempts: { type: Number, default: 0 },
  lastError: { type: String, default: null },

  // Manual review
  flaggedForReview: { type: Boolean, default: false, index: true },
  reviewReason: { type: String, default: null },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  reviewedAt: { type: Date, default: null },
  reviewNotes: { type: String, default: null },
}, {
  timestamps: true,
  collection: 'transactions',
  strict: true, // L4: explicit — reject unknown fields at DB write level
});

// Indexes for matching engine performance
transactionSchema.index({ toAddress: 1, amount: 1, status: 1 });
transactionSchema.index({ status: 1, detectedAt: -1 });
transactionSchema.index({ network: 1, blockNumber: -1 });
transactionSchema.index({ flaggedForReview: 1, status: 1 });

// Never expose internal review notes or error details externally
transactionSchema.methods.toSafeJSON = function () {
  const obj = this.toObject();
  delete obj.lastError;
  delete obj.__v;
  return obj;
};

// ─── IMMUTABILITY — protect confirmed blockchain records ────────────────────
// Blockchain-sourced fields are IMMUTABLE once transaction is confirmed.
// These fields come from on-chain data — modifying them would be evidence tampering.
const TX_FROZEN_FIELDS = new Set(['txHash', 'amount', 'fromAddress', 'toAddress', 'blockNumber', 'tokenContract', 'blockTimestamp', 'network']);

transactionSchema.pre('findOneAndUpdate', function (next) {
  this.model.findOne(this.getQuery(), { status: 1 }).lean().then((doc) => {
    if (doc && doc.status === 'confirmed') {
      const update = this.getUpdate() || {};
      const setKeys = Object.keys(update.$set || {});
      const frozen = setKeys.filter((k) => TX_FROZEN_FIELDS.has(k));
      if (frozen.length > 0) {
        return next(new Error(`SECURITY: Transaction in 'confirmed' state — blockchain fields immutable: ${frozen.join(', ')}`));
      }
    }
    next();
  }).catch(next);
});

transactionSchema.pre('deleteOne',         function (next) { next(new Error('SECURITY: Transaction records cannot be deleted')); });
transactionSchema.pre('deleteMany',        function (next) { next(new Error('SECURITY: Transaction records cannot be deleted')); });
transactionSchema.pre('findOneAndDelete',  function (next) { next(new Error('SECURITY: Transaction records cannot be deleted')); });
transactionSchema.pre('findOneAndReplace', function (next) { next(new Error('SECURITY: Transaction records cannot be deleted')); });

module.exports = mongoose.model('Transaction', transactionSchema);
