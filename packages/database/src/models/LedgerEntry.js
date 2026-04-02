'use strict';

const mongoose = require('mongoose');
const { LEDGER_ACCOUNTS, LEDGER_ENTRY_TYPE } = require('@xcg/common').constants;

/**
 * Double-Entry Ledger.
 * IMMUTABLE — no updates, no deletes.
 * Every money movement creates exactly 2 entries (debit + credit).
 */
const ledgerEntrySchema = new mongoose.Schema({
  entryId: { type: String, required: true, unique: true, index: true }, // led_xxx
  account: { type: String, enum: Object.values(LEDGER_ACCOUNTS), required: true, index: true },
  type: { type: String, enum: Object.values(LEDGER_ENTRY_TYPE), required: true },
  amount: { type: Number, required: true, min: 0.000001 },
  currency: { type: String, default: 'USDT' },

  // References
  merchantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant', index: true },
  invoiceId: { type: mongoose.Schema.Types.ObjectId, ref: 'Invoice', default: null },
  withdrawalId: { type: mongoose.Schema.Types.ObjectId, ref: 'Withdrawal', default: null },
  transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction', default: null },

  // Pairing
  counterpartEntryId: { type: String, required: true }, // The other side of double-entry
  description: { type: String, default: '' },

  // Idempotency
  idempotencyKey: { type: String, required: true, unique: true, index: true },

  // Running balance (cached, verified by reconciliation)
  balanceAfter: { type: Number, default: 0 },
}, {
  timestamps: true,
  collection: 'ledger_entries',
  // IMMUTABLE: disable update and delete
  strict: true,
});

// Performance indexes
ledgerEntrySchema.index({ merchantId: 1, account: 1, createdAt: -1 });
ledgerEntrySchema.index({ account: 1, type: 1, createdAt: -1 });

module.exports = mongoose.model('LedgerEntry', ledgerEntrySchema);
