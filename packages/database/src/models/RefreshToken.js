'use strict';

const mongoose = require('mongoose');

/**
 * Refresh Token — Separate collection for O(1) lookup.
 *
 * Why separate collection instead of embedded in User:
 *   - Indexed lookup by tokenHash (no full-user scan)
 *   - TTL index auto-deletes expired tokens (MongoDB handles cleanup)
 *   - Scales to millions of users without performance degradation
 *   - Each token is independently queryable
 */
const refreshTokenSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  tokenHash: { type: String, required: true, unique: true },
  ip: { type: String, default: null },
  userAgent: { type: String, default: null },
  expiresAt: { type: Date, required: true },
  isRevoked: { type: Boolean, default: false, index: true },
  revokedAt: { type: Date, default: null },
  replacedByToken: { type: String, default: null }, // Token rotation chain
  family: { type: String, required: true, index: true }, // Token family for reuse detection
}, {
  timestamps: true,
  collection: 'refresh_tokens',
});

// G3 FIX: expireAfterSeconds:0 means MongoDB deletes the document exactly when expiresAt passes.
// Previous value of 86400 added a 24-hour grace period — tokens sat in DB 24h after expiry.
// A payment system should not retain expired session tokens beyond their expiry time.
refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Compound indexes for common queries
refreshTokenSchema.index({ userId: 1, isRevoked: 1 });
refreshTokenSchema.index({ family: 1, isRevoked: 1 });

module.exports = mongoose.model('RefreshToken', refreshTokenSchema);
