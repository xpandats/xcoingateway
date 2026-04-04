'use strict';

const mongoose = require('mongoose');
const { DISPUTE_STATUS } = require('@xcg/common').constants;

const disputeSchema = new mongoose.Schema({
  disputeId:     { type: String, required: true, unique: true, index: true },
  invoiceId:     { type: mongoose.Schema.Types.ObjectId, ref: 'Invoice',     required: true, index: true },
  merchantId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant',    required: true, index: true },
  transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction', default: null },
  amount:        { type: Number, required: true, min: 0 },

  status: {
    type:    String,
    enum:    Object.values(DISPUTE_STATUS),
    default: DISPUTE_STATUS.OPENED,
    index:   true,
  },

  // Dispute details
  reason:   { type: String, required: true },
  evidence: [{ type: String }], // URLs or file references

  // Opened by (customer via merchant API, or admin)
  openedBy:  { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  openedAt:  { type: Date, default: Date.now },

  // Merchant response window
  merchantResponse:    { type: String, default: null },
  merchantRespondedAt: { type: Date,   default: null },
  merchantDeadline:    { type: Date,   default: null },

  // Escalation tracking (set when support escalates to admin review)
  escalatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  escalatedAt: { type: Date, default: null },

  // Notes history (append-only — each entry has timestamp + actor)
  notes: { type: String, default: '' },

  // CRITICAL: Ledger hold tracking
  // When a dispute is opened, funds move from merchant_receivable → dispute_hold
  // When resolved: either refund or release back to merchant_receivable
  holdLedgerEntryId:    { type: String, default: null }, // ID of the dispute_hold ledger entry
  holdAmount:           { type: Number, default: 0 },    // Amount frozen in dispute_hold
  fundsHeld:            { type: Boolean, default: false }, // Whether funds are currently frozen

  // Resolution
  resolution:   { type: String, default: null },
  resolvedBy:   { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  resolvedAt:   { type: Date,   default: null },
  refundTxHash: { type: String, default: null },
  refundAmount: { type: Number, default: 0 },
}, {
  timestamps: true,
  collection: 'disputes',
});

module.exports = mongoose.model('Dispute', disputeSchema);
