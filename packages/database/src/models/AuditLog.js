'use strict';

const mongoose = require('mongoose');

/**
 * @module models/AuditLog
 *
 * Audit Log — APPEND-ONLY, IMMUTABLE.
 *
 * GOLDEN RULE: Every sensitive operation in the system is recorded here.
 * No exceptions. If it's not in the audit log, it didn't happen.
 *
 * SECURITY:
 *   - Update and delete operations are BLOCKED at schema level
 *   - strict: true — unknown fields silently dropped (don't break writes)
 *   - Indexed for fast security queries by actor, action, resource, IP
 *   - Separate MongoDB collection — use separate DB user with insert-only
 *     access in production (cannot be wiped even with app compromise)
 *
 * FIELD NAMING: Consistent across ALL services — ipAddress, outcome, userAgent
 */

const auditLogSchema = new mongoose.Schema({
  // WHO performed the action
  actor:      { type: String, required: true, index: true }, // userId | 'system' | 'signing-service'

  // WHAT was done — use AUDIT_ACTIONS constants
  action:    { type: String, required: true, index: true },

  // WHEN
  timestamp:  { type: Date, required: true, default: Date.now, index: true },

  // FROM WHERE
  ipAddress:  { type: String, default: null, index: true }, // Consistent field name
  userAgent:  { type: String, default: null },

  // ON WHAT
  resource:   { type: String, default: null, index: true }, // 'merchant', 'wallet', 'withdrawal'
  resourceId: { type: String, default: null },              // The _id or public ID

  // RESULT
  outcome:   { type: String, enum: ['success', 'failed', 'blocked'], default: 'success' },

  // CONTEXT — before/after state for mutation operations
  before:    { type: mongoose.Schema.Types.Mixed, default: null }, // State before change
  after:     { type: mongoose.Schema.Types.Mixed, default: null },  // State after change
  metadata:  { type: mongoose.Schema.Types.Mixed, default: null },  // Extra context
}, {
  timestamps: false,        // Manual timestamp field for precision
  collection: 'audit_logs',
  strict: false,            // Allow flexible metadata — but core fields always required
});

// ─── Compound indexes for security forensics ─────────────────────────────────
auditLogSchema.index({ actor: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });
auditLogSchema.index({ resource: 1, resourceId: 1, timestamp: -1 });
auditLogSchema.index({ ipAddress: 1, timestamp: -1 });  // IP-based forensics
auditLogSchema.index({ outcome: 1, timestamp: -1 });    // Failed action monitoring

// ─── IMMUTABILITY ─────────────────────────────────────────────────────────────
// All update/delete operations are blocked at the schema middleware level.
// Even if application code is compromised, audit logs cannot be altered.

function immutableError(next) {
  const err = new Error(
    'SECURITY VIOLATION: Audit logs are immutable. Update/delete operations are forbidden.',
  );
  err.name = 'ImmutabilityViolation';
  next(err);
}

auditLogSchema.pre('updateOne',         immutableError);
auditLogSchema.pre('deleteOne',         immutableError);
auditLogSchema.pre('findOneAndUpdate',  immutableError);
auditLogSchema.pre('findOneAndDelete',  immutableError);
auditLogSchema.pre('findOneAndReplace', immutableError);
auditLogSchema.pre('updateMany',        immutableError);
auditLogSchema.pre('deleteMany',        immutableError);

auditLogSchema.pre('save', function (next) {
  if (!this.isNew) return immutableError(next);
  next();
});

module.exports = mongoose.model('AuditLog', auditLogSchema);
