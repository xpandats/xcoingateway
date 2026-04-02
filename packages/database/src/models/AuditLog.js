'use strict';

const mongoose = require('mongoose');

/**
 * Audit Log — APPEND-ONLY, IMMUTABLE.
 * No update or delete operations should ever be performed on this collection.
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
  timestamps: false, // We manage timestamp manually
  collection: 'audit_logs',
  strict: true,
});

auditLogSchema.index({ actor: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });
auditLogSchema.index({ resource: 1, resourceId: 1, timestamp: -1 });

module.exports = mongoose.model('AuditLog', auditLogSchema);
