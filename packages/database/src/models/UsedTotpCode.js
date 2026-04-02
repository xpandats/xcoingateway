'use strict';

const mongoose = require('mongoose');

/**
 * Used TOTP Code — Prevents replay of 2FA codes within their validity window.
 *
 * Each TOTP code is valid for 30 seconds. Without this, the same code
 * could be used multiple times within that window. This collection
 * tracks which codes have been used and auto-expires them via TTL.
 */
const usedTotpCodeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  code: { type: String, required: true },
  usedAt: { type: Date, required: true, default: Date.now },
}, {
  timestamps: false,
  collection: 'used_totp_codes',
});

// Compound unique index: same user can't use same code twice
usedTotpCodeSchema.index({ userId: 1, code: 1 }, { unique: true });

// TTL: auto-delete after 90 seconds (TOTP codes are valid for 30s, 3x buffer)
usedTotpCodeSchema.index({ usedAt: 1 }, { expireAfterSeconds: 90 });

module.exports = mongoose.model('UsedTotpCode', usedTotpCodeSchema);
