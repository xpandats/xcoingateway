'use strict';

/**
 * @module models/DeadLetterEntry
 *
 * Dead Letter Entry — Persistent record of failed queue messages.
 *
 * WHY THIS EXISTS:
 *   The DLQ in BullMQ/Redis is ephemeral — Redis restarts lose all dead letters.
 *   For a bank-grade system, every failed message MUST have a permanent DB record:
 *     - "Which withdrawal signing failed permanently?"
 *     - "Which transactions were dropped because of bad HMAC signatures?"
 *     - "How many DLQ entries have we had this month?"
 *
 *   The queueClient.js already sends messages to the DLQ Redis queue.
 *   This model creates a PERMANENT MongoDB record alongside the Redis entry.
 *
 * IMMUTABLE: Dead letter records are forensic evidence — no updates or deletes.
 */

const mongoose = require('mongoose');

const DLQ_SOURCE = Object.freeze({
  HMAC_INVALID:       'hmac_invalid',        // Message with bad HMAC signature
  MAX_RETRIES:        'max_retries',         // Exhausted all retry attempts
  VALIDATION_FAILED:  'validation_failed',   // Payload failed Joi validation
  PROCESSING_ERROR:   'processing_error',    // Unrecoverable processing error
  TIMEOUT:            'timeout',             // Job timed out
  MANUAL_REJECT:      'manual_reject',       // Admin manually rejected
});

const DLQ_STATUS = Object.freeze({
  PENDING:   'pending',     // Awaiting operator review
  RETRIED:   'retried',     // Operator retried the message
  RESOLVED:  'resolved',    // Operator marked as resolved (no action needed)
  PURGED:    'purged',      // Operator permanently discarded
});

const deadLetterEntrySchema = new mongoose.Schema({
  dlqId: { type: String, required: true, unique: true },  // dlq_xxx

  // Source queue
  sourceQueue:  { type: String, required: true, index: true },  // e.g. 'xcg:signing:request'
  jobId:        { type: String, default: null },                 // BullMQ job ID

  // Message content (original payload BEFORE failure)
  payload:      { type: mongoose.Schema.Types.Mixed, required: true },
  idempotencyKey: { type: String, default: null, index: true },

  // Failure context
  source: {
    type: String,
    enum: Object.values(DLQ_SOURCE),
    required: true,
    index: true,
  },
  error:        { type: String, required: true },     // Error message
  errorStack:   { type: String, default: null },      // Stack trace (internal only)
  attempts:     { type: Number, default: 0 },         // How many retries before DLQ

  // Service context
  serviceName:  { type: String, required: true, index: true },  // Which service rejected it
  workerName:   { type: String, default: null },                 // Specific worker instance

  // Resolution
  status: {
    type: String,
    enum: Object.values(DLQ_STATUS),
    default: DLQ_STATUS.PENDING,
    index: true,
  },
  resolvedBy:   { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  resolvedAt:   { type: Date, default: null },
  resolutionNotes: { type: String, default: '' },

  // Retry tracking (if operator retried)
  retriedAt:    { type: Date, default: null },
  retriedBy:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  retryJobId:   { type: String, default: null },      // New BullMQ job ID after retry
}, {
  timestamps: true,
  collection: 'dead_letter_entries',
  strict: true,
});

// Performance indexes
deadLetterEntrySchema.index({ sourceQueue: 1, status: 1, createdAt: -1 });
deadLetterEntrySchema.index({ serviceName: 1, createdAt: -1 });
deadLetterEntrySchema.index({ status: 1, createdAt: -1 });

// Block deletes — DLQ entries are forensic evidence
function immutableError(next) {
  next(new Error('SECURITY: DeadLetterEntry records are immutable — no deletes'));
}
deadLetterEntrySchema.pre('deleteOne',         function (next) { immutableError(next); });
deadLetterEntrySchema.pre('deleteMany',        function (next) { immutableError(next); });
deadLetterEntrySchema.pre('findOneAndDelete',  function (next) { immutableError(next); });
deadLetterEntrySchema.pre('findOneAndReplace', function (next) { immutableError(next); });

module.exports = mongoose.model('DeadLetterEntry', deadLetterEntrySchema);
module.exports.DLQ_SOURCE = DLQ_SOURCE;
module.exports.DLQ_STATUS = DLQ_STATUS;
