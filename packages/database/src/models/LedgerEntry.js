'use strict';

/**
 * @module models/LedgerEntry
 *
 * Double-Entry Ledger — IMMUTABLE.
 *
 * BANK-GRADE REQUIREMENTS:
 *   - Every money movement creates exactly 2 entries (debit + credit)
 *   - Entries are APPEND-ONLY: no updates, no deletes at schema level
 *   - Running balance verified by reconciliation
 *   - Idempotency key prevents duplicate entries
 *
 * IMMUTABILITY: Same enforcement as AuditLog — all update/delete
 * operations throw ImmutabilityViolation errors.
 */

const mongoose = require('mongoose');
const { LEDGER_ACCOUNTS, LEDGER_ENTRY_TYPE } = require('@xcg/common').constants;

const ledgerEntrySchema = new mongoose.Schema({
  entryId: { type: String, required: true, unique: true },  // led_xxx
  account: { type: String, enum: Object.values(LEDGER_ACCOUNTS), required: true, index: true },
  type: { type: String, enum: Object.values(LEDGER_ENTRY_TYPE), required: true },
  amount: { type: Number, required: true, min: 0.000001 },
  currency: { type: String, default: 'USDT' },

  // References
  merchantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant', index: true },
  invoiceId: { type: mongoose.Schema.Types.ObjectId, ref: 'Invoice', default: null },
  withdrawalId: { type: mongoose.Schema.Types.ObjectId, ref: 'Withdrawal', default: null },
  transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction', default: null },
  walletId:      { type: mongoose.Schema.Types.ObjectId, ref: 'Wallet', default: null, index: true },

  // Double-entry pairing
  counterpartEntryId: { type: String, required: true },
  description: { type: String, default: '' },

  // Idempotency
  idempotencyKey: { type: String, required: true, unique: true },

  // Running balance (cached, verified by reconciliation)
  balanceAfter: { type: Number, default: 0 },
}, {
  timestamps: true,
  collection: 'ledger_entries',
  strict: true,
});

// Performance indexes
ledgerEntrySchema.index({ merchantId: 1, account: 1, createdAt: -1 });
ledgerEntrySchema.index({ account: 1, type: 1, createdAt: -1 });

// ─── IMMUTABILITY ENFORCEMENT ────────────────────────────────
// Financial ledger entries MUST be immutable.

function immutableError(next) {
  const err = new Error('SECURITY VIOLATION: Ledger entries are immutable. Update/delete operations are forbidden.');
  err.name = 'ImmutabilityViolation';
  next(err);
}

ledgerEntrySchema.pre('updateOne', function (next) { immutableError(next); });
ledgerEntrySchema.pre('deleteOne', function (next) { immutableError(next); });
ledgerEntrySchema.pre('findOneAndUpdate', function (next) { immutableError(next); });
ledgerEntrySchema.pre('findOneAndDelete', function (next) { immutableError(next); });
ledgerEntrySchema.pre('findOneAndReplace', function (next) { immutableError(next); });
ledgerEntrySchema.pre('updateMany', function (next) { immutableError(next); });
ledgerEntrySchema.pre('deleteMany', function (next) { immutableError(next); });

ledgerEntrySchema.pre('save', function (next) {
  if (!this.isNew) {
    return immutableError(next);
  }
  next();
});

module.exports = mongoose.model('LedgerEntry', ledgerEntrySchema);
