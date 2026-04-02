'use strict';

const mongoose = require('mongoose');
const { TX_STATUS } = require('@xcg/common').constants;

const transactionSchema = new mongoose.Schema({
  // Blockchain data
  txHash: { type: String, required: true, unique: true, index: true },
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
});

// Indexes for matching engine performance
transactionSchema.index({ toAddress: 1, amount: 1, status: 1 });
transactionSchema.index({ status: 1, detectedAt: -1 });
transactionSchema.index({ network: 1, blockNumber: -1 });
transactionSchema.index({ flaggedForReview: 1, status: 1 });

module.exports = mongoose.model('Transaction', transactionSchema);
