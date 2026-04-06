'use strict';

/**
 * @module models/MerchantBalance
 *
 * Merchant Balance — Cached balance snapshot per merchant.
 *
 * WHY THIS EXISTS:
 *   The authoritative balance is always LedgerEntry.aggregate().
 *   But calling aggregate() on every dashboard load and API balance check
 *   is expensive — O(n) where n = number of ledger entries.
 *
 *   MerchantBalance is a CACHE:
 *     - Updated atomically after each ledger movement
 *     - Read by dashboard and withdrawal-eligibility checks for fast O(1) lookup
 *     - Periodically verified against LedgerEntry.aggregate() by reconciliation
 *
 * SECURITY:
 *   - All balance changes use $inc (no read-modify-write)
 *   - Never used as source of truth for withdrawals (withdrawal engine always
 *     re-aggregates from LedgerEntry before signing)
 *   - lastVerifiedAt tracks when reconciliation last confirmed accuracy
 *
 * IMPORTANT: If this cache drifts from reality, reconciliation will detect it
 * and flag a mismatch. The system continues operating using LedgerEntry.aggregate()
 * for all financial decisions.
 */

const mongoose = require('mongoose');

const merchantBalanceSchema = new mongoose.Schema({
  merchantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant', required: true, unique: true },

  // Cached balances (USDT)
  availableBalance:  { type: Number, default: 0 },   // Can withdraw this amount
  pendingBalance:    { type: Number, default: 0 },   // Awaiting confirmation
  frozenBalance:     { type: Number, default: 0 },   // Under dispute hold
  totalReceived:     { type: Number, default: 0 },   // Lifetime total received
  totalWithdrawn:    { type: Number, default: 0 },   // Lifetime total withdrawn
  totalRefunded:     { type: Number, default: 0 },   // Lifetime total refunded
  totalFees:         { type: Number, default: 0 },   // Lifetime platform fees

  // Currency
  currency: { type: String, default: 'USDT' },

  // Accuracy tracking
  lastUpdatedAt:   { type: Date, default: null },    // Last $inc operation
  lastVerifiedAt:  { type: Date, default: null },    // Last reconciliation verification
  isAccurate:      { type: Boolean, default: true },  // Set false if reconciliation finds drift
  driftAmount:     { type: Number, default: 0 },     // Difference detected by reconciliation

  // Statistics (for dashboard)
  invoiceCount:      { type: Number, default: 0 },
  withdrawalCount:   { type: Number, default: 0 },
  refundCount:       { type: Number, default: 0 },
  disputeCount:      { type: Number, default: 0 },
}, {
  timestamps: true,
  collection: 'merchant_balances',
  strict: true,
});

// Indexes
merchantBalanceSchema.index({ isAccurate: 1 });  // Fast lookup of drifted balances
merchantBalanceSchema.index({ availableBalance: 1 });  // For threshold-based auto-withdrawals

/**
 * Atomic balance increment using $inc.
 * Same pattern as Wallet.incrementBalance — never read-modify-write.
 *
 * @param {ObjectId} merchantId
 * @param {object} delta - { availableBalance, pendingBalance, frozenBalance, totalReceived, etc. }
 * @param {ClientSession} [session]
 * @returns {Promise<Document>}
 */
merchantBalanceSchema.statics.incrementBalance = async function (merchantId, delta, session = null) {
  const inc = {};
  const numKeys = ['availableBalance', 'pendingBalance', 'frozenBalance',
    'totalReceived', 'totalWithdrawn', 'totalRefunded', 'totalFees',
    'invoiceCount', 'withdrawalCount', 'refundCount', 'disputeCount'];

  for (const key of numKeys) {
    if (typeof delta[key] === 'number') inc[key] = delta[key];
  }

  if (Object.keys(inc).length === 0) {
    throw new Error('incrementBalance: at least one balance field must be provided');
  }

  const opts = { new: true, upsert: true };
  if (session) opts.session = session;

  return this.findOneAndUpdate(
    { merchantId },
    {
      $inc: inc,
      $set: { lastUpdatedAt: new Date() },
      $setOnInsert: { merchantId, currency: 'USDT' },
    },
    opts,
  );
};

module.exports = mongoose.model('MerchantBalance', merchantBalanceSchema);
