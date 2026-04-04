'use strict';

/**
 * @module controllers/auditChainController
 *
 * Audit Log Hash Chain Integrity — Mainnet Requirement #2.
 *
 * Provides endpoints to verify the cryptographic integrity of the audit
 * log chain. A broken chain means an audit entry was modified or deleted —
 * a security incident.
 *
 * Routes (super_admin + TOTP):
 *   GET  /admin/audit-chain/status  — Quick chain tip + stats (no verification)
 *   POST /admin/audit-chain/verify  — Full chain verification (O(n), expensive)
 */

const { AuditLog } = require('@xcg/database');
const asyncHandler = require('../utils/asyncHandler');
const logger = require('@xcg/logger').createLogger('audit-chain');

// ─── GET /admin/audit-chain/status ───────────────────────────────────────────

async function getAuditChainStatus(req, res) {
  const [totalEntries, lastEntry, firstEntry] = await Promise.all([
    AuditLog.countDocuments({}),
    AuditLog.findOne({}, { entryHash: 1, prevHash: 1, timestamp: 1, actor: 1, action: 1 })
      .sort({ timestamp: -1 })
      .lean(),
    AuditLog.findOne({}, { entryHash: 1, timestamp: 1 })
      .sort({ timestamp: 1 })
      .lean(),
  ]);

  // Count entries WITHOUT hash (pre-chain-upgrade entries or fallback writes)
  const unhashedCount = await AuditLog.countDocuments({ entryHash: null });

  res.json({
    success: true,
    data: {
      totalEntries,
      unhashedEntries: unhashedCount,
      hashedEntries:   totalEntries - unhashedCount,
      chainIntact:     unhashedCount === 0, // Quick heuristic — full verify is separate
      chainTip: lastEntry ? {
        entryHash: lastEntry.entryHash,
        prevHash:  lastEntry.prevHash,
        timestamp: lastEntry.timestamp,
        actor:     lastEntry.actor,
        action:    lastEntry.action,
      } : null,
      chainGenesis: firstEntry ? {
        entryHash: firstEntry.entryHash,
        timestamp: firstEntry.timestamp,
      } : null,
      message: unhashedCount > 0
        ? `WARNING: ${unhashedCount} entries have no hash — chain incomplete`
        : 'All entries have hashes. Run POST /verify for full cryptographic check.',
    },
  });
}

// ─── POST /admin/audit-chain/verify ──────────────────────────────────────────

async function verifyAuditChain(req, res) {
  // Default: verify last 10,000 entries (recent history)
  // Full audit: pass limit=0 for unlimited (can be very slow)
  const limit = Math.min(parseInt(req.query.limit || '10000', 10), 100000);

  logger.warn('AuditChain: chain verification started', {
    actor:  req.user.userId,
    limit,
    ip:     req.ip,
  });

  const startMs = Date.now();
  const result  = await AuditLog.verifyChain(limit);
  const durationMs = Date.now() - startMs;

  if (!result.valid) {
    // This is a CRITICAL SECURITY INCIDENT
    logger.error('AuditChain: CHAIN INTEGRITY VIOLATION DETECTED', {
      brokenAt:  result.brokenAt,
      scanned:   result.scanned,
      durationMs,
      verifiedBy: req.user.userId,
    });
  } else {
    logger.info('AuditChain: chain verified successfully', {
      scanned:   result.scanned,
      durationMs,
      verifiedBy: req.user.userId,
    });
  }

  res.json({
    success: true,
    data: {
      valid:      result.valid,
      scanned:    result.scanned,
      durationMs,
      limit,
      brokenAt:   result.brokenAt,     // null if valid
      severity:   result.valid ? 'none' : 'CRITICAL',
      message:    result.valid
        ? `Chain verified: ${result.scanned} entries checked — no tampering detected`
        : `SECURITY INCIDENT: Chain broken at entry ${result.brokenAt?._id}. Audit log may have been tampered with.`,
    },
  });
}

module.exports = {
  getAuditChainStatus: asyncHandler(getAuditChainStatus),
  verifyAuditChain:    asyncHandler(verifyAuditChain),
};
