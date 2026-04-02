'use strict';

const mongoose = require('mongoose');
const { DISPUTE_STATUS } = require('@xcg/common').constants;

const disputeSchema = new mongoose.Schema({
  disputeId: { type: String, required: true, unique: true, index: true },
  invoiceId: { type: mongoose.Schema.Types.ObjectId, ref: 'Invoice', required: true, index: true },
  merchantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant', required: true, index: true },
  transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction', default: null },
  amount: { type: Number, required: true },

  status: {
    type: String,
    enum: Object.values(DISPUTE_STATUS),
    default: DISPUTE_STATUS.OPENED,
    index: true,
  },

  reason: { type: String, required: true },
  evidence: [{ type: String }], // URLs or descriptions
  openedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  openedAt: { type: Date, default: Date.now },

  merchantResponse: { type: String, default: null },
  merchantRespondedAt: { type: Date, default: null },
  merchantDeadline: { type: Date, default: null },

  resolution: { type: String, default: null },
  resolvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  resolvedAt: { type: Date, default: null },
  refundTxHash: { type: String, default: null },
  refundAmount: { type: Number, default: 0 },
}, {
  timestamps: true,
  collection: 'disputes',
});

module.exports = mongoose.model('Dispute', disputeSchema);
