'use strict';

/**
 * @module models/Withdrawal
 *
 * Withdrawal — Merchant USDT payout requests.
 * High-value withdrawals require admin approval before signing.
 *
 * IMMUTABILITY: Once status is 'completed' or 'failed', core financial fields
 * (amount, fee, netAmount, toAddress, fromAddress, txHash) are permanently frozen.
 */

const mongoose = require('mongoose');
const { WITHDRAWAL_STATUS } = require('@xcg/common').constants;

const withdrawalSchema = new mongoose.Schema({
  withdrawalId: { type: String, required: true, unique: true },
  merchantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant', required: true, index: true },
  amount: { type: Number, required: true, min: 0.000001 },
  fee: { type: Number, default: 0 },
  netAmount: { type: Number, required: true },
  currency: { type: String, default: 'USDT' },
  network: { type: String, default: 'tron' },
  toAddress: {
    type: String,
    required: true,
    validate: {
      validator: (v) => /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(v),
      message: 'toAddress must be a valid TRC20 address (starts with T, 34 chars)',
    },
  },
  fromWalletId: { type: mongoose.Schema.Types.ObjectId, ref: 'Wallet', default: null },
  fromAddress:  { type: String, default: null },  // Our hot wallet address at broadcast time

  status: {
    type: String,
    enum: Object.values(WITHDRAWAL_STATUS),
    default: WITHDRAWAL_STATUS.REQUESTED,
    index: true,
  },

  // Blockchain
  txHash: { type: String, default: null, index: true },
  confirmations: { type: Number, default: 0 },
  broadcastAt: { type: Date, default: null },
  confirmedAt: { type: Date, default: null },

  // Approval (for high-value)
  requiresApproval: { type: Boolean, default: false },
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  approvedAt: { type: Date, default: null },
  rejectedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  rejectedAt: { type: Date, default: null },
  rejectionReason: { type: String, default: null },
  reviewNotes: { type: String, default: '' },  // Admin notes on approve/reject

  // Processing
  attempts: { type: Number, default: 0 },
  lastError: { type: String, default: null },   // Internal only — never exposed via API
  idempotencyKey: { type: String, sparse: true, unique: true }, // Prevent duplicate withdrawals

  // Gas tracking
  gasFeeRecordId: { type: mongoose.Schema.Types.ObjectId, ref: 'GasFeeRecord', default: null },

  requestedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
}, {
  timestamps: true,
  collection: 'withdrawals',
  strict: true,  // G6 FIX: Every financial model must explicitly reject unknown fields
});

withdrawalSchema.index({ merchantId: 1, status: 1, createdAt: -1 });

// ─── IMMUTABILITY — protect completed/failed financial records ──────────────
// Core financial fields CANNOT be changed once withdrawal is settled.
const FROZEN_FIELDS = new Set(['amount', 'fee', 'netAmount', 'toAddress', 'fromAddress', 'txHash', 'currency', 'network']);
const FINAL_STATUSES = new Set(['completed', 'failed']);

withdrawalSchema.pre('findOneAndUpdate', function (next) {
  this.model.findOne(this.getQuery(), { status: 1 }).lean().then((doc) => {
    if (doc && FINAL_STATUSES.has(doc.status)) {
      const update = this.getUpdate() || {};
      const setKeys = Object.keys(update.$set || {});
      const frozen = setKeys.filter((k) => FROZEN_FIELDS.has(k));
      if (frozen.length > 0) {
        return next(new Error(`SECURITY: Withdrawal in '${doc.status}' state — cannot modify: ${frozen.join(', ')}`));
      }
    }
    next();
  }).catch(next);
});

withdrawalSchema.pre('deleteOne',         function (next) { next(new Error('SECURITY: Withdrawal records cannot be deleted')); });
withdrawalSchema.pre('deleteMany',        function (next) { next(new Error('SECURITY: Withdrawal records cannot be deleted')); });
withdrawalSchema.pre('findOneAndDelete',  function (next) { next(new Error('SECURITY: Withdrawal records cannot be deleted')); });
withdrawalSchema.pre('findOneAndReplace', function (next) { next(new Error('SECURITY: Withdrawal records cannot be deleted')); });

// External-safe: hides internal retry error details
withdrawalSchema.methods.toSafeJSON = function () {
  const obj = this.toObject();
  delete obj.lastError;
  delete obj.__v;
  return obj;
};

module.exports = mongoose.model('Withdrawal', withdrawalSchema);
