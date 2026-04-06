'use strict';

/**
 * @module models/IpBlocklist
 *
 * IP Blocklist — Tracks blocked IPs from brute-force attacks, scanning, and abuse.
 *
 * WHY THIS EXISTS:
 *   BlacklistedWallet blocks wallet addresses.
 *   IpBlocklist blocks IP addresses.
 *
 *   Populated by:
 *     - ipRateLimit middleware (auto-block after threshold)
 *     - WAF middleware (scanner detection)
 *     - Admin manual block
 *     - Fraud engine (suspicious login patterns)
 *
 *   Checked before any processing (Nginx-level and application-level).
 *
 * EXPIRY: Some blocks are temporary (e.g., 24h after brute-force).
 *   expiresAt = null means permanent block.
 */

const mongoose = require('mongoose');

const IP_BLOCK_REASON = Object.freeze({
  BRUTE_FORCE:   'brute_force',     // Too many failed auth attempts
  RATE_LIMIT:    'rate_limit',      // Exceeded API rate limits repeatedly
  SCANNER:       'scanner',         // Detected scanning patterns (wp-admin, .env probe)
  FRAUD:         'fraud',           // Fraud engine flagged
  MANUAL_ADMIN:  'manual_admin',    // Admin manual block
  WAF_VIOLATION: 'waf_violation',   // WAF blocked suspicious payload
  SUSPICIOUS:    'suspicious',      // General suspicious behavior
});

const ipBlocklistSchema = new mongoose.Schema({
  ipAddress: { type: String, required: true, index: true, trim: true },

  // Why blocked
  reason: {
    type: String,
    enum: Object.values(IP_BLOCK_REASON),
    required: true,
  },
  notes: { type: String, default: '' },

  // Scope
  scope: { type: String, enum: ['global', 'auth', 'api', 'admin'], default: 'global' },

  // Severity tracking
  violationCount: { type: Number, default: 1 },            // How many violations before block
  firstViolationAt: { type: Date, default: Date.now },
  lastViolationAt:  { type: Date, default: Date.now },

  // Activity that triggered the block
  lastEndpoint:  { type: String, default: null },   // e.g. '/api/v1/auth/login'
  lastUserAgent: { type: String, default: null },

  // Block state
  isActive:  { type: Boolean, default: true, index: true },
  expiresAt: { type: Date, default: null, index: true },   // null = permanent

  // Who blocked it
  blockedBy: { type: String, default: 'system' },   // 'system' | userId
  unblockedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  unblockedAt: { type: Date, default: null },
  unblockReason: { type: String, default: null },
}, {
  timestamps: true,
  collection: 'ip_blocklist',
  strict: true,
});

// Indexes
ipBlocklistSchema.index({ ipAddress: 1, scope: 1 }, { unique: true });
ipBlocklistSchema.index({ isActive: 1, expiresAt: 1 });
ipBlocklistSchema.index({ reason: 1, createdAt: -1 });

/**
 * Check if an IP is currently blocked.
 * Auto-handles expired blocks.
 *
 * @param {string} ip - IP address
 * @param {string} [scope='global'] - 'global', 'auth', 'api', 'admin'
 * @returns {Promise<object|null>} Block entry or null
 */
ipBlocklistSchema.statics.isBlocked = async function (ip, scope = null) {
  const query = {
    ipAddress: ip,
    isActive: true,
    $or: [
      { expiresAt: null },
      { expiresAt: { $gt: new Date() } },
    ],
  };

  // If scope specified, check both global and specific scope
  if (scope) {
    query.$or.push({ scope: 'global' });
    query.scope = { $in: ['global', scope] };
    delete query.$or; // Rebuild
    return this.findOne({
      ipAddress: ip,
      isActive: true,
      scope: { $in: ['global', scope] },
      $or: [
        { expiresAt: null },
        { expiresAt: { $gt: new Date() } },
      ],
    }).lean();
  }

  return this.findOne(query).lean();
};

module.exports = mongoose.model('IpBlocklist', ipBlocklistSchema);
module.exports.IP_BLOCK_REASON = IP_BLOCK_REASON;
