'use strict';

/**
 * @module models/Refund
 *
 * Refund — Tracks individual refund requests and their on-chain execution.
 *
 * BANK-GRADE REQUIREMENTS:
 *   - Refund can originate from a dispute resolution OR standalone merchant request
 *   - Amount validation: cannot refund more than the original invoice amount
 *   - Links to LedgerEntry for accounting integrity
 *   - Immutable after completion — blockchain evidence
 *   - Idempotency key to prevent duplicate refund processing
 *
 * FLOW:
 *   1. Refund created (status: pending) — from dispute resolution or merchant panel
 *   2. Validated: sufficient balance, original invoiceId exists, amount <= invoice netAmount
 *   3. Queued for signing → signed → broadcast → confirmed
 *   4. LedgerEntry created: debit merchant_receivable, credit refund_outgoing
 *   5. Webhook sent: refund.completed
 */

const mongoose = require('mongoose');

const REFUND_STATUS = Object.freeze({
  PENDING:          'pending',          // Created, awaiting processing
  APPROVED:         'approved',         // Admin approved (for manual refunds)
  QUEUED:           'queued',           // Sent to withdrawal/signing queue
  SIGNING:          'signing',          // Being signed in Zone 3
  BROADCAST:        'broadcast',        // Signed tx broadcast to chain
  CONFIRMING:       'confirming',       // Awaiting blockchain confirmations
  COMPLETED:        'completed',        // On-chain confirmed
  FAILED:           'failed',           // Signing or broadcast failed
  REJECTED:         'rejected',         // Admin rejected refund request
});

const REFUND_REASON = Object.freeze({
  DISPUTE_RESOLVED: 'dispute_resolved', // Dispute ruled in customer favor
  MERCHANT_REQUEST: 'merchant_request', // Merchant voluntarily refunds
  OVERPAYMENT:      'overpayment',      // Customer overpaid invoice
  DUPLICATE:        'duplicate',        // Duplicate payment detected
  SERVICE_ISSUE:    'service_issue',    // Platform-side issue
  ADMIN_DECISION:   'admin_decision',   // Admin-initiated refund
});

const refundSchema = new mongoose.Schema({
  refundId: { type: String, required: true, unique: true }, // ref_xxx

  // Source
  invoiceId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Invoice', required: true, index: true },
  merchantId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant', required: true, index: true },
  disputeId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Dispute', default: null, index: true },

  // Amounts
  originalAmount: { type: Number, required: true, min: 0.000001 },  // Original invoice amount
  refundAmount:   { type: Number, required: true, min: 0.000001 },  // Amount being refunded
  currency:       { type: String, default: 'USDT' },
  network:        { type: String, default: 'tron' },

  // Destination
  toAddress:   { type: String, required: true },  // Customer's original sending address
  fromWalletId:{ type: mongoose.Schema.Types.ObjectId, ref: 'Wallet', default: null },

  // Reason
  reason: {
    type: String,
    enum: Object.values(REFUND_REASON),
    required: true,
  },
  notes: { type: String, default: '' },

  // Status
  status: {
    type: String,
    enum: Object.values(REFUND_STATUS),
    default: REFUND_STATUS.PENDING,
    index: true,
  },

  // Blockchain
  txHash:         { type: String, default: null, index: true },
  confirmations:  { type: Number, default: 0 },
  broadcastAt:    { type: Date, default: null },
  confirmedAt:    { type: Date, default: null },

  // Ledger
  ledgerEntryId:  { type: String, default: null },  // LedgerEntry.entryId reference

  // Processing
  attempts:      { type: Number, default: 0 },
  lastError:     { type: String, default: null },

  // Audit
  requestedBy:   { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  approvedBy:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  approvedAt:    { type: Date, default: null },
  rejectedBy:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  rejectedAt:    { type: Date, default: null },
  rejectionReason: { type: String, default: null },

  // Idempotency
  idempotencyKey: { type: String, sparse: true, unique: true },
}, {
  timestamps: true,
  collection: 'refunds',
  strict: true,
});

// Indexes
refundSchema.index({ merchantId: 1, status: 1, createdAt: -1 });
refundSchema.index({ invoiceId: 1, status: 1 });
refundSchema.index({ status: 1, createdAt: -1 });

// Validation: refundAmount cannot exceed originalAmount
refundSchema.pre('save', function (next) {
  if (this.refundAmount > this.originalAmount) {
    return next(new Error(`SECURITY: Refund amount (${this.refundAmount}) exceeds original invoice amount (${this.originalAmount})`));
  }
  next();
});

// Immutability: completed/failed refunds are immutable
function refundImmutableError(next) {
  next(new Error('SECURITY: Refund records are immutable — delete/replace forbidden'));
}
refundSchema.pre('deleteOne',         function (next) { refundImmutableError(next); });
refundSchema.pre('deleteMany',        function (next) { refundImmutableError(next); });
refundSchema.pre('findOneAndDelete',  function (next) { refundImmutableError(next); });
refundSchema.pre('findOneAndReplace', function (next) { refundImmutableError(next); });

// Safe JSON — hide internal error details
refundSchema.methods.toSafeJSON = function () {
  const obj = this.toObject();
  delete obj.lastError;
  delete obj.__v;
  return obj;
};

module.exports = mongoose.model('Refund', refundSchema);
module.exports.REFUND_STATUS = REFUND_STATUS;
module.exports.REFUND_REASON = REFUND_REASON;
