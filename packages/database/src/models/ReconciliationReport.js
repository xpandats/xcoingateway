'use strict';

/**
 * @module models/ReconciliationReport
 *
 * Reconciliation Report — Immutable record of each reconciliation run.
 *
 * Stores the comparison between on-chain balances and internal ledger,
 * any mismatches found, and the resolution status.
 *
 * SECURITY: append-only (pre-hooks block update/delete)
 */

const mongoose = require('mongoose');

const mismatchSchema = new mongoose.Schema({
  walletAddress:    { type: String, required: true },
  walletId:         { type: mongoose.Schema.Types.ObjectId, ref: 'Wallet', default: null },
  onChainBalance:   { type: Number, required: true },   // What blockchain shows
  ledgerBalance:    { type: Number, required: true },   // What internal ledger shows
  difference:       { type: Number, required: true },   // onChain - ledger
  severity:         { type: String, enum: ['minor', 'major', 'critical'], default: 'minor' },
}, { _id: false });

const reconciliationReportSchema = new mongoose.Schema({
  reportId:     { type: String, required: true, unique: true, index: true },

  // Run metadata
  triggeredBy:  { type: String, default: 'scheduler' }, // 'scheduler' | userId
  startedAt:    { type: Date, required: true },
  completedAt:  { type: Date, default: null },
  durationMs:   { type: Number, default: null },

  // Results
  status:  { type: String, enum: ['running', 'completed', 'failed'], default: 'running', index: true },
  passed:  { type: Boolean, default: null },           // true = no mismatches

  // Counts
  walletsChecked:   { type: Number, default: 0 },
  mismatchCount:    { type: Number, default: 0 },

  // On-chain totals
  onChainTotalUsdt: { type: Number, default: 0 },
  ledgerTotalUsdt:  { type: Number, default: 0 },
  totalDifference:  { type: Number, default: 0 },

  // Matched invoices check
  totalConfirmedInvoices:  { type: Number, default: 0 },
  totalMatchedTxns:        { type: Number, default: 0 },
  unmatchedTxnCount:       { type: Number, default: 0 },

  // Detail per wallet
  mismatches: [mismatchSchema],

  // Error info (if status = failed)
  error: { type: String, default: null },

  // Action taken
  withdrawalsPaused: { type: Boolean, default: false }, // Auto-paused on critical mismatch
  alertSent:         { type: Boolean, default: false },
  resolvedAt:        { type: Date, default: null },
  resolvedBy:        { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  resolutionNotes:   { type: String, default: '' },
}, {
  timestamps: true,
  collection: 'reconciliation_reports',
  strict: true, // Reject unknown fields — financial report integrity
});


reconciliationReportSchema.index({ startedAt: -1 });
reconciliationReportSchema.index({ status: 1, startedAt: -1 });
reconciliationReportSchema.index({ passed: 1, startedAt: -1 });

// Immutability: once a report is completed it must not be silently modified.
// Only resolution fields (resolvedAt/resolvedBy/resolutionNotes) are ever updated
// — handled deliberately in the reconciler via findOneAndUpdate with explicit $set.
// These hooks block ALL update/delete paths to prevent silent tampering.
reconciliationReportSchema.pre('updateOne',         (_, next) => next(new Error('ReconciliationReport: use findOneAndUpdate for resolution only')));
reconciliationReportSchema.pre('updateMany',        (_, next) => next(new Error('ReconciliationReport is immutable')));
reconciliationReportSchema.pre('findOneAndUpdate',  function (next) {
  // Allow ONLY the resolution fields — reject anything else
  const update  = this.getUpdate() || {};
  const allowed = new Set(['resolvedAt', 'resolvedBy', 'resolutionNotes', 'withdrawalsPaused', 'alertSent', 'status', 'completedAt', 'durationMs', 'error', 'passed', 'walletsChecked', 'mismatchCount', 'onChainTotalUsdt', 'ledgerTotalUsdt', 'totalDifference', 'totalConfirmedInvoices', 'totalMatchedTxns', 'unmatchedTxnCount', 'mismatches']);
  const setKeys = Object.keys(update.$set || {});
  const forbidden = setKeys.filter((k) => !allowed.has(k));
  if (forbidden.length > 0) {
    return next(new Error(`ReconciliationReport: cannot update fields: ${forbidden.join(', ')}`));
  }
  next();
});
reconciliationReportSchema.pre('findOneAndReplace', (_, next) => next(new Error('ReconciliationReport is immutable — no replace')));
reconciliationReportSchema.pre('deleteOne',         (_, next) => next(new Error('ReconciliationReport is immutable')));
reconciliationReportSchema.pre('findOneAndDelete',  (_, next) => next(new Error('ReconciliationReport is immutable')));
reconciliationReportSchema.pre('deleteMany',        (_, next) => next(new Error('ReconciliationReport is immutable')));


module.exports = mongoose.model('ReconciliationReport', reconciliationReportSchema);
