'use strict';

/**
 * @module models/LoginEvent
 *
 * Login Event — Persistent record of every auth attempt (success and failure).
 *
 * WHY THIS EXISTS (from Description.txt):
 *   "Device/IP change detection → re-authentication required"
 *   "Account lockout after 5 failed attempts (15 min cooldown)"
 *
 *   AuditLog covers all sensitive actions, but login forensics need dedicated:
 *     - Geolocation tracking (IP → country) for anomaly detection
 *     - Device fingerprint tracking for new-device detection
 *     - Failed login pattern analysis (brute-force, credential stuffing)
 *     - Per-user login history for "trust this device" feature
 *     - All this with efficient indexes (AuditLog is general-purpose)
 *
 * SECURITY: select:false on sensitiveFields. TTL auto-deletes after 180 days.
 * IMMUTABLE: Login events are forensic evidence — no updates or deletes.
 */

const mongoose = require('mongoose');

const LOGIN_RESULT = Object.freeze({
  SUCCESS:            'success',
  FAILED_PASSWORD:    'failed_password',
  FAILED_TOTP:        'failed_totp',
  ACCOUNT_LOCKED:     'account_locked',
  ACCOUNT_DISABLED:   'account_disabled',
  IP_BLOCKED:         'ip_blocked',
  RATE_LIMITED:       'rate_limited',
  NEW_DEVICE_BLOCK:   'new_device_block',
});

const loginEventSchema = new mongoose.Schema({
  // Who
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true },
  email:     { type: String, required: true, lowercase: true, index: true },
  role:      { type: String, default: null },

  // Result
  result: {
    type: String,
    enum: Object.values(LOGIN_RESULT),
    required: true,
    index: true,
  },

  // Where
  ipAddress:    { type: String, required: true, index: true },
  ipHash:       { type: String, default: null },     // SHA-256 of IP for privacy-safe storage
  country:      { type: String, default: null },     // Resolved from IP (if geo service available)
  city:         { type: String, default: null },

  // Device
  userAgent:       { type: String, default: null },
  deviceHash:      { type: String, default: null, index: true },  // Hash of UA + screen + timezone
  isKnownDevice:   { type: Boolean, default: false },              // Seen this device before?
  isNewIp:         { type: Boolean, default: false },              // First login from this IP?
  isNewCountry:    { type: Boolean, default: false },              // First login from this country?

  // 2FA
  totpRequired:    { type: Boolean, default: false },
  totpProvided:    { type: Boolean, default: false },

  // Security context
  failedAttempts:  { type: Number, default: 0 },     // Current streak at time of login
  lockedUntil:     { type: Date, default: null },    // If account was locked
  riskScore:       { type: Number, default: 0, min: 0, max: 100 }, // Login risk score

  // Session
  sessionId:       { type: String, default: null },  // RefreshToken family
}, {
  timestamps: true,
  collection: 'login_events',
  strict: true,
});

// TTL: auto-delete login events after 180 days
loginEventSchema.index({ createdAt: 1 }, { expireAfterSeconds: 180 * 24 * 60 * 60 });

// Performance indexes for forensics
loginEventSchema.index({ userId: 1, createdAt: -1 });
loginEventSchema.index({ email: 1, result: 1, createdAt: -1 });
loginEventSchema.index({ ipAddress: 1, result: 1, createdAt: -1 });
loginEventSchema.index({ deviceHash: 1, userId: 1, createdAt: -1 });
loginEventSchema.index({ isNewDevice: 1, isNewIp: 1, createdAt: -1 });
loginEventSchema.index({ result: 1, createdAt: -1 });

// Immutability — login events are forensic evidence
function immutableError(next) {
  next(new Error('SECURITY: LoginEvent is immutable'));
}
loginEventSchema.pre('updateOne',         function (next) { immutableError(next); });
loginEventSchema.pre('updateMany',        function (next) { immutableError(next); });
loginEventSchema.pre('findOneAndUpdate',  function (next) { immutableError(next); });
loginEventSchema.pre('deleteOne',         function (next) { immutableError(next); });
loginEventSchema.pre('deleteMany',        function (next) { immutableError(next); });
loginEventSchema.pre('findOneAndDelete',  function (next) { immutableError(next); });
loginEventSchema.pre('findOneAndReplace', function (next) { immutableError(next); });

loginEventSchema.pre('save', function (next) {
  if (!this.isNew) return immutableError(next);
  next();
});

/**
 * Check if a device hash is known for a user.
 * Used by auth service to detect new-device logins.
 */
loginEventSchema.statics.isKnownDeviceForUser = async function (userId, deviceHash) {
  if (!deviceHash) return false;
  const entry = await this.findOne({
    userId,
    deviceHash,
    result: 'success',
  }).lean();
  return !!entry;
};

/**
 * Get recent failed login count for an email (across all IPs).
 * Used for velocity-based lockout.
 */
loginEventSchema.statics.getRecentFailedCount = async function (email, windowMs = 15 * 60 * 1000) {
  return this.countDocuments({
    email: email.toLowerCase(),
    result: { $in: ['failed_password', 'failed_totp'] },
    createdAt: { $gte: new Date(Date.now() - windowMs) },
  });
};

module.exports = mongoose.model('LoginEvent', loginEventSchema);
module.exports.LOGIN_RESULT = LOGIN_RESULT;
