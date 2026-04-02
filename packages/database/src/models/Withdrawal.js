'use strict';

const mongoose = require('mongoose');
const { WITHDRAWAL_STATUS } = require('@xcg/common').constants;

const withdrawalSchema = new mongoose.Schema({
  withdrawalId: { type: String, required: true, unique: true, index: true },
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
  lastError: { type: String, default: null },
  idempotencyKey: { type: String, sparse: true, index: true },

  requestedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
}, {
  timestamps: true,
  collection: 'withdrawals',
});

withdrawalSchema.index({ merchantId: 1, status: 1, createdAt: -1 });

module.exports = mongoose.model('Withdrawal', withdrawalSchema);
