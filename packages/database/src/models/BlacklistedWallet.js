'use strict';

/**
 * @module models/BlacklistedWallet
 *
 * Wallet address blacklist — blocks specific Tron/EVM addresses from transacting.
 *
 * Sources:
 *   - Internal (manual admin add)
 *   - OFAC sanctions (admin bulk import)
 *   - Auto-flagged (system detects suspicious pattern)
 *
 * SECURITY: `txHash: null` guard in matching engine prevents matching
 * blacklisted-sender invoices. This model is the authoritative source.
 */

const mongoose = require('mongoose');

const BLACKLIST_REASON = Object.freeze({
  OFAC_SANCTIONS:   'ofac_sanctions',    // US OFAC sanctioned address
  INTERNAL_RISK:    'internal_risk',     // Internal risk decision
  FRAUD_DETECTED:   'fraud_detected',    // Auto-detected fraud pattern
  CHARGEBACK:       'chargeback',        // Prior chargeback
  MANUAL_ADMIN:     'manual_admin',      // Manual admin decision
  VELOCITY_ABUSE:   'velocity_abuse',    // Too many txs in short time
});

const blacklistedWalletSchema = new mongoose.Schema({
  address: {
    type:     String,
    required: true,
    unique:   true,
    index:    true,
    lowercase: true,  // Normalise — all comparisons lower-cased
    trim:     true,
  },
  network: {
    type:    String,
    default: 'tron',
    index:   true,
  },

  reason: {
    type:    String,
    enum:    Object.values(BLACKLIST_REASON),
    required:true,
  },
  notes: { type: String, default: '' },

  // Who added it
  addedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref:  'User',
    default: null,
  },
  autoFlagged: { type: Boolean, default: false }, // true = system detected

  // Optional: linked invoice/tx that triggered it
  linkedTxHash:     { type: String, default: null },
  linkedInvoiceId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Invoice', default: null },

  // Expiry — null = permanent
  expiresAt: { type: Date, default: null, index: true },

  isActive: { type: Boolean, default: true, index: true },
}, {
  timestamps: true,
  collection: 'blacklisted_wallets',
  strict:     true,
});

blacklistedWalletSchema.index({ address: 1, network: 1 });
blacklistedWalletSchema.index({ isActive: 1, expiresAt: 1 });
blacklistedWalletSchema.index({ autoFlagged: 1, createdAt: -1 });

/**
 * Check if a specific address is currently blacklisted.
 * Handles expired entries automatically.
 *
 * @param {string} address
 * @param {string} [network='tron']
 * @returns {Promise<object|null>} The blacklist entry or null
 */
blacklistedWalletSchema.statics.isBlacklisted = async function (address, network = 'tron') {
  return this.findOne({
    address:  address.toLowerCase(),
    network,
    isActive: true,
    $or: [
      { expiresAt: null },
      { expiresAt: { $gt: new Date() } },
    ],
  }).lean();
};

module.exports = mongoose.model('BlacklistedWallet', blacklistedWalletSchema);
module.exports.BLACKLIST_REASON = BLACKLIST_REASON;
