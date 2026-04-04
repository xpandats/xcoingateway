'use strict';

/**
 * @module models/FraudEvent
 *
 * Append-only fraud event log — every fraud check result is recorded.
 *
 * IMMUTABLE: No updates or deletes. Fraud events are audit evidence.
 * HIGH-RISK data — used for dispute resolution and regulatory compliance.
 */

const mongoose = require('mongoose');

const FRAUD_EVENT_TYPE = Object.freeze({
  BLACKLIST_HIT:       'blacklist_hit',         // Address on blacklist
  VELOCITY_EXCEEDED:   'velocity_exceeded',     // Too many txs/invoices in window
  RISK_SCORE_HIGH:     'risk_score_high',       // Risk score above threshold
  SUSPICIOUS_VOLUME:   'suspicious_volume',     // Sudden volume spike
  AMOUNT_ANOMALY:      'amount_anomaly',        // Unusual amount for this merchant
  IP_ANOMALY:          'ip_anomaly',            // Login from new IP/country
  DUPLICATE_TX:        'duplicate_tx',          // Duplicate transaction attempt
  AUTO_BLOCKED:        'auto_blocked',          // System auto-paused merchant
});

const FRAUD_ACTION = Object.freeze({
  ALLOWED:       'allowed',      // Risk accepted, transaction proceeds
  BLOCKED:       'blocked',      // Transaction hard-blocked
  FLAGGED:       'flagged',      // Transaction proceeds but flagged for review
  MERCHANT_PAUSED: 'merchant_paused', // Entire merchant auto-paused
});

const fraudEventSchema = new mongoose.Schema({
  // What triggered this event
  eventType: {
    type:     String,
    enum:     Object.values(FRAUD_EVENT_TYPE),
    required: true,
    index:    true,
  },

  // What action was taken
  action: {
    type:     String,
    enum:     Object.values(FRAUD_ACTION),
    required: true,
    index:    true,
  },

  // Risk score at time of check (0–100)
  riskScore: { type: Number, default: 0, min: 0, max: 100 },

  // Context
  merchantId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant', default: null, index: true },
  invoiceId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Invoice',  default: null, index: true },
  txHash:      { type: String, default: null, index: true },
  fromAddress: { type: String, default: null, lowercase: true },
  toAddress:   { type: String, default: null, lowercase: true },
  amount:      { type: Number, default: null },
  network:     { type: String, default: 'tron' },

  // IP / user context (for login fraud detection)
  ipAddress:   { type: String, default: null },
  userAgent:   { type: String, default: null },
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },

  // Detail payload (rule that triggered, threshold values, etc.)
  details: { type: mongoose.Schema.Types.Mixed, default: {} },

  // Human-readable reason
  reason: { type: String, required: true },
}, {
  timestamps: true,
  collection: 'fraud_events',
  strict:     true,
});

// Block all mutations — fraud log is immutable
fraudEventSchema.pre('findOneAndUpdate', function () {
  throw new Error('SECURITY: FraudEvent is immutable — no updates allowed');
});
fraudEventSchema.pre('updateOne', function () {
  throw new Error('SECURITY: FraudEvent is immutable — no updates allowed');
});
fraudEventSchema.pre('updateMany', function () {
  throw new Error('SECURITY: FraudEvent is immutable — no updates allowed');
});
fraudEventSchema.pre('deleteOne', function () {
  throw new Error('SECURITY: FraudEvent is immutable — no deletes allowed');
});
fraudEventSchema.pre('deleteMany', function () {
  throw new Error('SECURITY: FraudEvent is immutable — no deletes allowed');
});

fraudEventSchema.index({ merchantId: 1, createdAt: -1 });
fraudEventSchema.index({ fromAddress: 1, createdAt: -1 });
fraudEventSchema.index({ eventType: 1, action: 1, createdAt: -1 });
fraudEventSchema.index({ riskScore: -1, createdAt: -1 });

module.exports = mongoose.model('FraudEvent', fraudEventSchema);
module.exports.FRAUD_EVENT_TYPE = FRAUD_EVENT_TYPE;
module.exports.FRAUD_ACTION     = FRAUD_ACTION;
