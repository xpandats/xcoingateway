'use strict';

/**
 * @module models/Settlement
 *
 * Settlement — Batch payout records for merchant fund settlement.
 *
 * BANK-GRADE REQUIREMENTS:
 *   - Every settlement maps to exactly one set of ledger entries
 *   - Settlement records are immutable once status reaches 'completed' or 'failed'
 *   - Tracks the period covered, amounts, and associated withdrawal
 *   - Double-entry ledger integration via settlementLedgerEntryIds
 *
 * FLOW:
 *   1. Settlement created (status: pending) — triggered by auto-withdrawal schedule or admin
 *   2. Merchant balance aggregated from LedgerEntry for settlement period
 *   3. Withdrawal created → signing → broadcast → confirmed
 *   4. Settlement marked 'completed' with txHash
 */

const mongoose = require('mongoose');

const SETTLEMENT_STATUS = Object.freeze({
  PENDING:     'pending',        // Created, awaiting processing
  PROCESSING:  'processing',     // Withdrawal being signed/broadcast
  COMPLETED:   'completed',      // On-chain confirmed
  FAILED:      'failed',         // Signing or broadcast failed
  CANCELLED:   'cancelled',      // Admin cancelled before processing
});

const settlementSchema = new mongoose.Schema({
  settlementId: { type: String, required: true, unique: true },  // stl_xxx

  // Merchant
  merchantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant', required: true, index: true },

  // Period covered
  periodStart: { type: Date, required: true },        // Start of settlement window
  periodEnd:   { type: Date, required: true },        // End of settlement window
  frequency:   { type: String, enum: ['daily', 'weekly', 'manual', 'threshold'], default: 'manual' },

  // Amounts (USDT)
  grossAmount:   { type: Number, required: true, min: 0 },  // Total merchant receivable for period
  feeAmount:     { type: Number, required: true, min: 0 },  // Platform fees deducted
  netAmount:     { type: Number, required: true, min: 0 },  // Amount actually sent to merchant
  currency:      { type: String, default: 'USDT' },
  network:       { type: String, default: 'tron' },

  // Invoice references — which invoices are covered by this settlement
  invoiceCount:  { type: Number, default: 0 },
  invoiceIds:    [{ type: mongoose.Schema.Types.ObjectId, ref: 'Invoice' }],

  // Withdrawal link
  withdrawalId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Withdrawal', default: null },
  toAddress:     { type: String, required: true },  // Merchant's TRC20 address at time of settlement

  // Blockchain
  txHash:        { type: String, default: null, index: true },

  // Status
  status: {
    type: String,
    enum: Object.values(SETTLEMENT_STATUS),
    default: SETTLEMENT_STATUS.PENDING,
    index: true,
  },

  // Ledger integration
  ledgerEntryIds: [{ type: String }],  // LedgerEntry.entryId references

  // Processing
  processedAt: { type: Date, default: null },
  completedAt: { type: Date, default: null },
  failedAt:    { type: Date, default: null },
  lastError:   { type: String, default: null },

  // Audit
  createdBy:   { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },  // Admin or 'system'
  approvedBy:  { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
}, {
  timestamps: true,
  collection: 'settlements',
  strict: true,
});

// Indexes
settlementSchema.index({ merchantId: 1, periodStart: -1 });
settlementSchema.index({ status: 1, createdAt: -1 });
settlementSchema.index({ merchantId: 1, status: 1 });

// Immutability: completed/failed settlements cannot be modified
settlementSchema.pre('findOneAndUpdate', function (next) {
  // Query the doc being updated to check current status
  this.model.findOne(this.getQuery(), { status: 1 }).lean().then((doc) => {
    if (doc && (doc.status === 'completed' || doc.status === 'failed')) {
      const update = this.getUpdate();
      const setKeys = Object.keys(update.$set || {});
      const allowed = new Set(['lastError']); // Only error annotation allowed on final records
      const forbidden = setKeys.filter((k) => !allowed.has(k));
      if (forbidden.length > 0) {
        return next(new Error(`SECURITY: Settlement in '${doc.status}' state is immutable. Cannot update: ${forbidden.join(', ')}`));
      }
    }
    next();
  }).catch(next);
});

settlementSchema.pre('deleteOne',         function (next) { next(new Error('SECURITY: Settlement records are immutable')); });
settlementSchema.pre('deleteMany',        function (next) { next(new Error('SECURITY: Settlement records are immutable')); });
settlementSchema.pre('findOneAndDelete',  function (next) { next(new Error('SECURITY: Settlement records are immutable')); });
settlementSchema.pre('findOneAndReplace', function (next) { next(new Error('SECURITY: Settlement records are immutable')); });

module.exports = mongoose.model('Settlement', settlementSchema);
module.exports.SETTLEMENT_STATUS = SETTLEMENT_STATUS;
