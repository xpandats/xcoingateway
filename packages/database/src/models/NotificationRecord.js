'use strict';

/**
 * @module models/NotificationRecord
 *
 * Notification Record — Audit trail for ALL system alerts and notifications.
 *
 * WHY THIS EXISTS:
 *   WebhookDelivery tracks merchant-facing webhook delivery.
 *   NotificationRecord tracks INTERNAL system alerts:
 *     - Telegram alerts sent to admin
 *     - Email alerts (future)
 *     - SMS alerts (future)
 *     - Slack/Discord (future)
 *
 *   Without this:
 *     - "Did we actually send an alert when reconciliation failed?" → unknown
 *     - "How many alerts did we send today?" → no data
 *     - "Is the alert channel working?" → you only know when it fails during an emergency
 *
 * IMMUTABLE: Notification delivery records are audit evidence.
 */

const mongoose = require('mongoose');

const NOTIFICATION_CHANNEL = Object.freeze({
  TELEGRAM:  'telegram',
  EMAIL:     'email',
  SLACK:     'slack',
  DISCORD:   'discord',
  SMS:       'sms',
});

const NOTIFICATION_SEVERITY = Object.freeze({
  INFO:     'info',       // Routine notifications
  WARNING:  'warning',    // Needs attention
  CRITICAL: 'critical',   // Immediate action required
  ALERT:    'alert',      // System-level emergency
});

const NOTIFICATION_STATUS = Object.freeze({
  SENT:     'sent',       // Successfully delivered to channel
  FAILED:   'failed',     // Delivery failed
  PENDING:  'pending',    // Queued for delivery
  SKIPPED:  'skipped',    // Skipped (channel not configured, or duplicate suppression)
});

const notificationRecordSchema = new mongoose.Schema({
  notificationId: { type: String, required: true, unique: true },  // ntf_xxx

  // Channel
  channel: {
    type: String,
    enum: Object.values(NOTIFICATION_CHANNEL),
    required: true,
    index: true,
  },

  // Severity
  severity: {
    type: String,
    enum: Object.values(NOTIFICATION_SEVERITY),
    required: true,
    index: true,
  },

  // Content
  subject:  { type: String, required: true },           // Alert subject/title
  message:  { type: String, required: true },           // Full message body
  category: { type: String, required: true, index: true }, // e.g. 'reconciliation', 'fraud', 'system'

  // Delivery
  status: {
    type: String,
    enum: Object.values(NOTIFICATION_STATUS),
    default: NOTIFICATION_STATUS.PENDING,
    index: true,
  },
  sentAt:      { type: Date, default: null },
  deliveryMs:  { type: Number, default: null },     // Time taken to deliver
  lastError:   { type: String, default: null },

  // Channel-specific metadata
  telegramChatId:   { type: String, default: null },
  telegramMsgId:    { type: String, default: null },  // For message reference
  emailTo:          { type: String, default: null },
  emailMessageId:   { type: String, default: null },

  // Context
  serviceOrigin: { type: String, required: true },    // Which service sent this (e.g. 'reconciliation-service')
  resourceType:  { type: String, default: null },     // e.g. 'reconciliation_report', 'fraud_event'
  resourceId:    { type: String, default: null },     // ID of the triggering resource

  // Duplicate suppression
  dedupeKey:     { type: String, default: null, index: true },  // Same key = suppress within window
}, {
  timestamps: true,
  collection: 'notification_records',
  strict: true,
});

// Performance indexes
notificationRecordSchema.index({ channel: 1, status: 1, createdAt: -1 });
notificationRecordSchema.index({ category: 1, severity: 1, createdAt: -1 });
notificationRecordSchema.index({ serviceOrigin: 1, createdAt: -1 });

// Immutability — notification records are audit evidence
function immutableError(next) {
  next(new Error('SECURITY: NotificationRecord is immutable'));
}
notificationRecordSchema.pre('updateOne',         function (next) { immutableError(next); });
notificationRecordSchema.pre('updateMany',        function (next) { immutableError(next); });
notificationRecordSchema.pre('deleteOne',         function (next) { immutableError(next); });
notificationRecordSchema.pre('deleteMany',        function (next) { immutableError(next); });
notificationRecordSchema.pre('findOneAndDelete',  function (next) { immutableError(next); });
notificationRecordSchema.pre('findOneAndReplace', function (next) { immutableError(next); });

// Allow findOneAndUpdate ONLY for status + sentAt + deliveryMs (initial delivery recording)
notificationRecordSchema.pre('findOneAndUpdate', function (next) {
  const update = this.getUpdate() || {};
  const allowed = new Set(['status', 'sentAt', 'deliveryMs', 'lastError', 'telegramMsgId', 'emailMessageId']);
  const setKeys = Object.keys(update.$set || {});
  const forbidden = setKeys.filter((k) => !allowed.has(k));
  if (forbidden.length > 0) {
    return next(new Error(`NotificationRecord: cannot update fields: ${forbidden.join(', ')}`));
  }
  next();
});

module.exports = mongoose.model('NotificationRecord', notificationRecordSchema);
module.exports.NOTIFICATION_CHANNEL  = NOTIFICATION_CHANNEL;
module.exports.NOTIFICATION_SEVERITY = NOTIFICATION_SEVERITY;
module.exports.NOTIFICATION_STATUS   = NOTIFICATION_STATUS;
