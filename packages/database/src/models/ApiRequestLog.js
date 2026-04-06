'use strict';

/**
 * @module models/ApiRequestLog
 *
 * API Request Log — Forensic-level tracking of merchant API activity.
 *
 * WHY THIS EXISTS:
 *   AuditLog tracks sensitive actions (login, config change, withdrawal).
 *   ApiRequestLog tracks EVERY merchant API call for:
 *     - Per-key usage analytics and billing
 *     - Security forensics ("when was this API key used? from which IP?")
 *     - Rate limit debugging ("why was this merchant rate-limited?")
 *     - SLA measurement (response times per endpoint)
 *     - Fraud pattern detection (unusual API call patterns)
 *
 * TTL: Auto-deletes after 90 days (configurable) to prevent unbounded growth.
 * APPEND-ONLY: No updates or deletes by application code.
 */

const mongoose = require('mongoose');

const apiRequestLogSchema = new mongoose.Schema({
  // Request identification
  requestId:   { type: String, required: true, unique: true, index: true },  // X-Request-ID header

  // Who made the request
  merchantId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant', required: true, index: true },
  apiKeyId:    { type: String, required: true, index: true },  // Merchant's keyId (NOT the secret)
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },  // If JWT-based auth

  // Request details
  method:      { type: String, required: true },     // GET, POST, PUT, DELETE
  path:        { type: String, required: true },     // /api/v1/payments
  statusCode:  { type: Number, required: true },     // 200, 400, 429, 500
  responseMs:  { type: Number, required: true },     // Response time in milliseconds

  // Client info
  ipAddress:   { type: String, required: true, index: true },
  userAgent:   { type: String, default: null },

  // Security
  hmacValid:     { type: Boolean, default: true },   // Was HMAC signature valid?
  rateLimited:   { type: Boolean, default: false, index: true },  // Was this request rate-limited?
  blocked:       { type: Boolean, default: false, index: true },  // Was this request blocked by WAF/fraud?

  // Body size tracking (prevent abuse)
  requestBodySize:  { type: Number, default: 0 },    // Bytes
  responseBodySize: { type: Number, default: 0 },    // Bytes

  // Error context (non-sensitive)
  errorCode:    { type: String, default: null },      // e.g. 'INSUFFICIENT_BALANCE', 'RATE_LIMITED'
  errorMessage: { type: String, default: null },      // Short safe message (never include stack traces)

  // Idempotency
  idempotencyKey: { type: String, default: null, index: true },  // If present
  idempotencyHit: { type: Boolean, default: false },             // Was this a cache hit?
}, {
  timestamps: true,
  collection: 'api_request_logs',
  strict: true,
});

// TTL: auto-delete logs after 90 days
apiRequestLogSchema.index({ createdAt: 1 }, { expireAfterSeconds: 90 * 24 * 60 * 60 });

// Performance indexes for forensic queries
apiRequestLogSchema.index({ merchantId: 1, createdAt: -1 });
apiRequestLogSchema.index({ apiKeyId: 1, createdAt: -1 });
apiRequestLogSchema.index({ ipAddress: 1, createdAt: -1 });
apiRequestLogSchema.index({ statusCode: 1, createdAt: -1 });
apiRequestLogSchema.index({ rateLimited: 1, createdAt: -1 });
apiRequestLogSchema.index({ path: 1, method: 1, createdAt: -1 });

// Append-only — no updates or deletes
function immutableError(next) {
  next(new Error('SECURITY: ApiRequestLog is append-only'));
}
apiRequestLogSchema.pre('updateOne',         function (next) { immutableError(next); });
apiRequestLogSchema.pre('updateMany',        function (next) { immutableError(next); });
apiRequestLogSchema.pre('findOneAndUpdate',  function (next) { immutableError(next); });
apiRequestLogSchema.pre('deleteOne',         function (next) { immutableError(next); });
apiRequestLogSchema.pre('deleteMany',        function (next) { immutableError(next); });
apiRequestLogSchema.pre('findOneAndDelete',  function (next) { immutableError(next); });
apiRequestLogSchema.pre('findOneAndReplace', function (next) { immutableError(next); });

apiRequestLogSchema.pre('save', function (next) {
  if (!this.isNew) return immutableError(next);
  next();
});

module.exports = mongoose.model('ApiRequestLog', apiRequestLogSchema);
