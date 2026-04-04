'use strict';

/**
 * Immutable Audit Logger — FIXED.
 *
 * Normalized field names: ip → ipAddress, outcome added.
 * Accepts both `ip` and `ipAddress` for backward compatibility.
 */

const { createLogger } = require('./logger');
const logger = createLogger('audit');

function createAuditLogger(AuditLogModel) {
  if (!AuditLogModel) {
    return {
      log: async (entry) => { logger.info('AUDIT (no DB)', entry); },
    };
  }

  return {
    /**
     * Record an immutable audit log entry.
     *
     * @param {object} entry
     * @param {string} entry.actor       - UserId or service name
     * @param {string} entry.action      - From AUDIT_ACTIONS constants
     * @param {string} [entry.ip]        - Alias for ipAddress (legacy support)
     * @param {string} [entry.ipAddress] - Request IP (preferred)
     * @param {string} [entry.userAgent]
     * @param {string} [entry.resource]  - 'merchant', 'wallet', etc.
     * @param {string} [entry.resourceId]
     * @param {string} [entry.outcome]   - 'success' | 'failed' | 'blocked'
     * @param {object} [entry.before]    - State before action
     * @param {object} [entry.after]     - State after action
     * @param {object} [entry.metadata]  - Extra context
     */
    log: async ({
      actor,
      action,
      ip         = null,
      ipAddress  = null,
      userAgent  = null,
      resource   = null,
      resourceId = null,
      outcome    = 'success',
      before     = null,
      after      = null,
      metadata   = null,
    }) => {
      try {
        await AuditLogModel.create({
          actor,
          action,
          timestamp:  new Date(),
          ipAddress:  ipAddress || ip, // Normalize ip→ipAddress
          userAgent,
          resource,
          resourceId,
          outcome,
          before,
          after,
          metadata,
        });
      } catch (err) {
        logger.error('Failed to write audit log', {
          error:      err.message,
          auditEntry: { actor, action, resource, resourceId },
        });
      }
    },
  };
}

module.exports = { createAuditLogger };
