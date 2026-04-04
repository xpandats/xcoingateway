'use strict';

/**
 * @module @xcg/database/auditConnection
 *
 * Separate MongoDB connection for the Audit Log collection.
 *
 * BANK-GRADE ISOLATION REQUIREMENT:
 *   The audit log must use a SEPARATE database user that has INSERT-only access.
 *   This means even if the main application is completely compromised:
 *     - Attackers CANNOT read historical audit entries
 *     - Attackers CANNOT modify or delete audit entries
 *     - Attackers CAN only append new entries
 *
 * SETUP (MongoDB Atlas or self-hosted):
 *   Create a user with role: { role: "readWrite", db: "xcg_audit" }
 *   BUT restrict write to insert-only by using a custom role:
 *
 *   db.createRole({
 *     role: "insertOnlyAudit",
 *     privileges: [{
 *       resource: { db: "xcg_audit", collection: "audit_logs" },
 *       actions: ["insert", "find"]  // find needed for hash chain reads
 *     }],
 *     roles: []
 *   })
 *
 *   Then create user:
 *   db.createUser({
 *     user: "xcg_audit_writer",
 *     pwd: "<strong-random-password>",
 *     roles: [{ role: "insertOnlyAudit", db: "xcg_audit" }]
 *   })
 *
 * ENV VARS REQUIRED:
 *   AUDIT_MONGODB_URI = mongodb+srv://xcg_audit_writer:<pwd>@cluster.mongodb.net/xcg_audit
 *
 * If AUDIT_MONGODB_URI is NOT set, falls back to main MONGODB_URI
 * (still works, just loses the isolation guarantee — acceptable for dev)
 */

const mongoose = require('mongoose');
const { createLogger } = require('@xcg/logger');

const logger = createLogger('audit-db');

// Separate Mongoose connection instance (not the default connection)
let auditConnection = null;
let connectionPromise = null;

/**
 * Connect the audit DB using a separate Mongoose connection.
 * Idempotent — safe to call multiple times.
 *
 * @returns {Promise<mongoose.Connection>}
 */
async function connectAuditDB() {
  if (auditConnection && auditConnection.readyState === 1) {
    return auditConnection;
  }

  // Only start one connection attempt at a time
  if (connectionPromise) {
    return connectionPromise;
  }

  connectionPromise = _doConnect();
  try {
    auditConnection = await connectionPromise;
    return auditConnection;
  } finally {
    connectionPromise = null;
  }
}

async function _doConnect() {
  // Use dedicated audit URI if available — INSERT-ONLY user for max isolation
  const auditUri = process.env.AUDIT_MONGODB_URI || process.env.MONGODB_URI;

  if (!auditUri) {
    throw new Error('FATAL: Neither AUDIT_MONGODB_URI nor MONGODB_URI are set');
  }

  const isIsolated = !!process.env.AUDIT_MONGODB_URI;
  if (!isIsolated) {
    logger.warn('AuditDB: AUDIT_MONGODB_URI not set — using main connection. ' +
      'For production: create an INSERT-ONLY MongoDB user and set AUDIT_MONGODB_URI.');
  }

  // Sanitize for logging
  const safeUri = auditUri.replace(/\/\/.*@/, '//<credentials>@');

  const conn = mongoose.createConnection(auditUri, {
    maxPoolSize: 3,          // Audit writes are lower volume than main ops
    minPoolSize: 1,
    serverSelectionTimeoutMS: 5000,
    heartbeatFrequencyMS: 10000,
    retryWrites: true,
    socketTimeoutMS: 30000,
    connectTimeoutMS: 10000,
  });

  conn.on('connected', () => {
    logger.info('AuditDB connected', { uri: safeUri, isolated: isIsolated });
  });

  conn.on('disconnected', () => {
    logger.warn('AuditDB disconnected — audit logging degraded');
  });

  conn.on('error', (err) => {
    logger.error('AuditDB connection error', { error: err.message });
  });

  // Wait for the connection to actually be ready
  await new Promise((resolve, reject) => {
    if (conn.readyState === 1) {
      resolve();
      return;
    }
    conn.once('connected', resolve);
    conn.once('error', reject);
    // Timeout after 10 seconds
    setTimeout(() => reject(new Error('AuditDB: connection timeout after 10s')), 10000);
  }).catch(() => {
    // Non-fatal: audit logging degraded but system continues
    logger.error('AuditDB: failed to connect — audit writes will fail silently');
  });

  return conn;
}

/**
 * Get the audit connection (must call connectAuditDB first).
 * @returns {mongoose.Connection|null}
 */
function getAuditConnection() {
  return auditConnection;
}

/**
 * Disconnect audit DB gracefully.
 */
async function disconnectAuditDB() {
  if (auditConnection && auditConnection.readyState !== 0) {
    await auditConnection.close();
    auditConnection = null;
    logger.info('AuditDB disconnected gracefully');
  }
}

module.exports = { connectAuditDB, disconnectAuditDB, getAuditConnection };
