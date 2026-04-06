'use strict';

/**
 * @module models/PaymentSession
 *
 * Payment Session — Customer-facing payment flow state.
 *
 * WHY THIS EXISTS:
 *   The Invoice is the backend record. The PaymentSession is the customer-facing
 *   flow state: QR code data, timer, real-time status polling, and display metadata.
 *
 *   Without this:
 *     - No way to track payment page visits and abandonment rates
 *     - No structured data for payment page rendering (QR, timer, amount display)
 *     - No session-level rate limiting (prevents spamming payment page)
 *     - Invoice model gets polluted with UI-layer concerns
 *
 * SESSION LIFECYCLE:
 *   1. Customer visits /pay/:invoiceId → PaymentSession created (status: active)
 *   2. Payment page renders with QR code, countdown, and polling endpoint
 *   3. When blockchain tx detected → status: detected
 *   4. When confirmed → status: completed
 *   5. Timer expires → status: expired
 *   6. TTL index auto-deletes expired sessions (cleanup)
 */

const mongoose = require('mongoose');

const SESSION_STATUS = Object.freeze({
  ACTIVE:    'active',     // Payment page is live, timer running
  DETECTED:  'detected',   // Blockchain tx detected, awaiting confirmations
  COMPLETED: 'completed',  // Payment confirmed
  EXPIRED:   'expired',    // Timer expired without payment
  CANCELLED: 'cancelled',  // Merchant cancelled the invoice
});

const paymentSessionSchema = new mongoose.Schema({
  sessionId: { type: String, required: true, unique: true },  // ps_xxx

  // Invoice reference
  invoiceId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Invoice', required: true, index: true },
  merchantId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant', required: true, index: true },

  // Payment display data (snapshot at session creation time)
  displayAmount:  { type: Number, required: true },           // Unique amount to display
  displayAddress: { type: String, required: true },           // Wallet address for QR code
  currency:       { type: String, default: 'USDT' },
  network:        { type: String, default: 'tron' },

  // QR code data
  qrData: { type: String, required: true },                   // Full QR payload string

  // Timing
  expiresAt: { type: Date, required: true, index: true },     // Countdown timer end
  timeoutMs: { type: Number, required: true },                // Original timeout duration

  // Status
  status: {
    type: String,
    enum: Object.values(SESSION_STATUS),
    default: SESSION_STATUS.ACTIVE,
    index: true,
  },

  // Visitor tracking (anonymized for privacy)
  visitorIpHash: { type: String, default: null },     // SHA-256 of IP (privacy)
  visitorAgent:  { type: String, default: null },     // User-agent truncated
  pageViews:     { type: Number, default: 1 },        // How many times page loaded
  lastViewedAt:  { type: Date, default: Date.now },

  // Merchant branding (cached at creation time)
  merchantName: { type: String, default: '' },
  merchantLogo: { type: String, default: '' },
}, {
  timestamps: true,
  collection: 'payment_sessions',
  strict: true,
});

// TTL: auto-delete expired sessions after 24 hours (cleanup ephemeral data)
paymentSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 86400 });

// Performance indexes
paymentSessionSchema.index({ invoiceId: 1, status: 1 });
paymentSessionSchema.index({ status: 1, expiresAt: 1 });

module.exports = mongoose.model('PaymentSession', paymentSessionSchema);
module.exports.SESSION_STATUS = SESSION_STATUS;
