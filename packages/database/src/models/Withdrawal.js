'use strict';

/**
 * @module models/Withdrawal
 *
 * Withdrawal — Merchant USDT payout requests.
 * High-value withdrawals require admin approval before signing.
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
  toAddress: { type: String, required: true },
  fromWalletId: { type: mongoose.Schema.Types.ObjectId, ref: 'Wallet', default: null },

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

  // Processing
  attempts: { type: Number, default: 0 },
  lastError: { type: String, default: null },   // Internal only — never exposed via API
  idempotencyKey: { type: String, sparse: true, unique: true }, // Prevent duplicate withdrawals

  requestedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
}, {
  timestamps: true,
  collection: 'withdrawals',
});

withdrawalSchema.index({ merchantId: 1, status: 1, createdAt: -1 });

// External-safe: hides internal retry error details
withdrawalSchema.methods.toSafeJSON = function () {
  const obj = this.toObject();
  delete obj.lastError;
  delete obj.__v;
  return obj;
};

module.exports = mongoose.model('Withdrawal', withdrawalSchema);
