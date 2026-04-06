'use strict';

/**
 * @module models/KeyRotationLog
 *
 * Key Rotation Log — Tracks every cryptographic key rotation event.
 *
 * WHY THIS EXISTS (from Description.txt):
 *   - JWT secret: rotatable with key ID in token header (old tokens valid until expiry)
 *   - Master encryption key: rotation plan with re-encryption migration script
 *   - Merchant API keys: regeneratable, old key has 24h grace period
 *   - Internal service tokens: auto-rotate on schedule
 *
 *   Without tracking:
 *     - "When was the JWT secret last rotated?" → unknown
 *     - "Which wallets were re-encrypted during key rotation?" → unknown
 *     - "Is the old API key still in its grace period?" → guesswork
 *     - "Who initiated the rotation?" → no audit trail
 *
 * IMMUTABLE: Key rotation records are security audit evidence.
 */

const mongoose = require('mongoose');

const KEY_TYPE = Object.freeze({
  JWT_SECRET:          'jwt_secret',
  MASTER_ENCRYPTION:   'master_encryption_key',
  MERCHANT_API_KEY:    'merchant_api_key',
  MERCHANT_WEBHOOK:    'merchant_webhook_secret',
  INTERNAL_SERVICE:    'internal_service_token',
  QUEUE_HMAC:          'queue_hmac_secret',
});

const ROTATION_STATUS = Object.freeze({
  INITIATED:   'initiated',     // Rotation started
  IN_PROGRESS: 'in_progress',   // Re-encryption/migration running
  COMPLETED:   'completed',     // New key active, old key deprecated
  FAILED:      'failed',        // Rotation failed, old key still active
  ROLLED_BACK: 'rolled_back',   // Failed rotation reverted
});

const keyRotationLogSchema = new mongoose.Schema({
  rotationId: { type: String, required: true, unique: true },  // rot_xxx

  // What was rotated
  keyType: {
    type: String,
    enum: Object.values(KEY_TYPE),
    required: true,
    index: true,
  },

  // Scope — whose key was rotated
  merchantId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant', default: null, index: true },
  serviceName: { type: String, default: null },  // For internal service tokens

  // Key identifiers (NEVER store actual key values)
  oldKeyId:    { type: String, default: null },   // Key ID / fingerprint of outgoing key
  newKeyId:    { type: String, required: true },   // Key ID / fingerprint of incoming key

  // Grace period (old key still valid during transition)
  gracePeriodMs:   { type: Number, default: 0 },      // How long old key remains valid
  graceExpiresAt:  { type: Date, default: null },     // When old key becomes invalid

  // Migration tracking (for master encryption key rotation)
  walletsReEncrypted: { type: Number, default: 0 },   // Count of wallets re-encrypted
  totalWallets:       { type: Number, default: 0 },   // Total wallets needing re-encryption

  // Status
  status: {
    type: String,
    enum: Object.values(ROTATION_STATUS),
    default: ROTATION_STATUS.INITIATED,
    index: true,
  },

  // Processing
  startedAt:   { type: Date, default: Date.now },
  completedAt: { type: Date, default: null },
  failedAt:    { type: Date, default: null },
  durationMs:  { type: Number, default: null },
  error:       { type: String, default: null },

  // Audit
  initiatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  reason:      { type: String, default: 'scheduled' },  // 'scheduled', 'security_breach', 'manual', 'policy'
}, {
  timestamps: true,
  collection: 'key_rotation_logs',
  strict: true,
});

// Performance indexes
keyRotationLogSchema.index({ keyType: 1, createdAt: -1 });
keyRotationLogSchema.index({ status: 1, createdAt: -1 });
keyRotationLogSchema.index({ merchantId: 1, keyType: 1, createdAt: -1 });

// Immutability — rotation records are security audit evidence
function immutableError(next) {
  next(new Error('SECURITY: KeyRotationLog is immutable'));
}
keyRotationLogSchema.pre('deleteOne',         function (next) { immutableError(next); });
keyRotationLogSchema.pre('deleteMany',        function (next) { immutableError(next); });
keyRotationLogSchema.pre('findOneAndDelete',  function (next) { immutableError(next); });
keyRotationLogSchema.pre('findOneAndReplace', function (next) { immutableError(next); });

// Allow findOneAndUpdate ONLY for status progression + completion fields
keyRotationLogSchema.pre('findOneAndUpdate', function (next) {
  const update = this.getUpdate() || {};
  const allowed = new Set(['status', 'completedAt', 'failedAt', 'durationMs', 'error',
    'walletsReEncrypted', 'graceExpiresAt']);
  const setKeys = Object.keys(update.$set || {});
  const forbidden = setKeys.filter((k) => !allowed.has(k));
  if (forbidden.length > 0) {
    return next(new Error(`KeyRotationLog: cannot update fields: ${forbidden.join(', ')}`));
  }
  next();
});

module.exports = mongoose.model('KeyRotationLog', keyRotationLogSchema);
module.exports.KEY_TYPE        = KEY_TYPE;
module.exports.ROTATION_STATUS = ROTATION_STATUS;
