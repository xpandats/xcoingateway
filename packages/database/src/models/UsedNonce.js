'use strict';

/**
 * @module models/UsedNonce
 *
 * Nonce Deduplication Store — Anti-Replay Protection.
 *
 * BANK-GRADE REQUIREMENTS:
 *   - Every merchant API request must include a unique nonce
 *   - Nonce + merchantId combination tracked here
 *   - TTL index auto-deletes expired nonces (same window as timestamp tolerance)
 *   - Unique compound index ensures exact reuse detection in one DB round-trip
 *
 * If a nonce is already in this collection → replay attack → reject request.
 */

const mongoose = require('mongoose');
const { AUTH } = require('@xcg/common').constants;

const usedNonceSchema = new mongoose.Schema({
  nonce: { type: String, required: true },
  merchantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant', required: true },
  usedAt: { type: Date, default: Date.now },
}, {
  collection: 'used_nonces',
  timestamps: false, // Only need usedAt
  strict: true, // Anti-replay store: never accept unknown injected fields
});


// Unique compound index: same nonce can exist for different merchants
// but NOT for the same merchant twice.
usedNonceSchema.index({ nonce: 1, merchantId: 1 }, { unique: true });

// TTL index: auto-delete nonces older than the tolerance window
// Keeps the collection small — only current nonces stored.
usedNonceSchema.index(
  { usedAt: 1 },
  { expireAfterSeconds: AUTH.NONCE_TTL_SECONDS },
);

module.exports = mongoose.model('UsedNonce', usedNonceSchema);
