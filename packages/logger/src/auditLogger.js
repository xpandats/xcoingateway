'use strict';

/**
 * Immutable Audit Logger.
 *
 * Records every sensitive action in the system.
 * Audit entries are APPEND-ONLY — no updates, no deletes.
 *
 * Each entry contains:
 *   - actor (userId or service name)
 *   - action (from AUDIT_ACTIONS constants)
 *   - timestamp (ISO 8601 UTC)
 *   - ip (request IP)
 *   - userAgent
 *   - resource (what was affected)
 *   - resourceId (ID of affected resource)
 *   - before (state before change, if applicable)
 *   - after (state after change, if applicable)
 *   - metadata (additional context)
 *
 * Storage: MongoDB 'audit_logs' collection with NO update/delete operations.
 * The AuditLog model does NOT have findOneAndUpdate or deleteOne methods.
 */

const { createLogger } = require('./logger');
const logger = createLogger('audit');

/**
 * Create an audit logger instance.
 * Requires a mongoose model to persist entries.
 *
 * @param {object} AuditLogModel - Mongoose model for audit_logs collection
 * @returns {object} Audit logger with log() method
 */
function createAuditLogger(AuditLogModel) {
  if (!AuditLogModel) {
    // If no model provided, log to structured logger only (for early startup)
    return {
      log: async (entry) => {
        logger.info('AUDIT (no DB)', entry);
      },
    };
  }

  return {
    /**
     * Record an audit log entry.
     * This is fire-and-forget — audit logging should never block business logic.
     * Failures are logged but do not throw.
     *
     * @param {object} entry
     * @param {string} entry.actor - User ID or service name performing the action
     * @param {string} entry.action - Action type (from AUDIT_ACTIONS)
     * @param {string} [entry.ip] - Request IP address
     * @param {string} [entry.userAgent] - Request user agent
     * @param {string} [entry.resource] - Resource type (e.g., 'merchant', 'wallet')
     * @param {string} [entry.resourceId] - ID of the affected resource
     * @param {object} [entry.before] - State before the action
     * @param {object} [entry.after] - State after the action
     * @param {object} [entry.metadata] - Additional context
     */
    log: async ({
      actor,
      action,
      ip = null,
      userAgent = null,
      resource = null,
      resourceId = null,
      before = null,
      after = null,
      metadata = null,
    }) => {
      try {
        await AuditLogModel.create({
          actor,
          action,
          timestamp: new Date(),
          ip,
          userAgent,
          resource,
          resourceId,
          before,
          after,
          metadata,
        });
      } catch (err) {
        // Audit logging must NEVER crash the service
        // Log to structured logger as fallback
        logger.error('Failed to write audit log', {
          error: err.message,
          auditEntry: { actor, action, resource, resourceId },
        });
      }
    },
  };
}

module.exports = { createAuditLogger };
