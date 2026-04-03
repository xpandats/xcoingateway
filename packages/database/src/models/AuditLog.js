'use strict';

const mongoose = require('mongoose');

/**
 * Audit Log — APPEND-ONLY, IMMUTABLE.
 *
 * SECURITY: Update and delete operations are disabled at the schema level.
 * This ensures the audit trail cannot be tampered with via application code,
 * even if an attacker gains access to the application layer.
 *
 * Only direct MongoDB shell access can modify these records (which requires
 * separate DB credentials and should be restricted in production).
 */
const auditLogSchema = new mongoose.Schema({
  actor: { type: String, required: true, index: true }, // userId or 'system'
  action: { type: String, required: true, index: true }, // From AUDIT_ACTIONS
  timestamp: { type: Date, required: true, default: Date.now, index: true },
  ip: { type: String, default: null },
  userAgent: { type: String, default: null },
  resource: { type: String, default: null, index: true }, // 'merchant', 'wallet', etc.
  resourceId: { type: String, default: null },
  before: { type: mongoose.Schema.Types.Mixed, default: null },
  after: { type: mongoose.Schema.Types.Mixed, default: null },
  metadata: { type: mongoose.Schema.Types.Mixed, default: null },
}, {
  timestamps: false,
  collection: 'audit_logs',
  strict: true,
});

auditLogSchema.index({ actor: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });
auditLogSchema.index({ resource: 1, resourceId: 1, timestamp: -1 });

// ─── IMMUTABILITY ENFORCEMENT ────────────────────────────────
// Disable all update and delete operations at the schema level.
// Any attempt to call these will throw an error.

function immutableError(next) {
  const err = new Error('SECURITY VIOLATION: Audit logs are immutable. Update/delete operations are forbidden.');
  err.name = 'ImmutabilityViolation';
  next(err);
}

// Block instance-level operations
auditLogSchema.pre('updateOne', function (next) { immutableError(next); });
auditLogSchema.pre('deleteOne', function (next) { immutableError(next); });
auditLogSchema.pre('findOneAndUpdate', function (next) { immutableError(next); });
auditLogSchema.pre('findOneAndDelete', function (next) { immutableError(next); });
auditLogSchema.pre('findOneAndReplace', function (next) { immutableError(next); });

// Block model-level operations
auditLogSchema.pre('updateMany', function (next) { immutableError(next); });
auditLogSchema.pre('deleteMany', function (next) { immutableError(next); });

// Block save on existing documents (only new inserts allowed)
auditLogSchema.pre('save', function (next) {
  if (!this.isNew) {
    return immutableError(next);
  }
  next();
});

module.exports = mongoose.model('AuditLog', auditLogSchema);
