'use strict';

/**
 * @module controllers/dlqController
 *
 * Dead Letter Queue (DLQ) Monitor — Mainnet Requirement #4.
 *
 * Data sources:
 *   1. DeadLetterEntry (MongoDB) — permanent, compliance-grade records
 *   2. Redis BullMQ DLQ queue    — live queue state (ephemeral)
 *
 * CRITICAL: DLQ entries must be monitored. A payment that ends up in the DLQ
 * means money moved on-chain but the system failed to process it internally.
 *
 * Routes (super_admin + TOTP for mutations):
 *   GET    /admin/dlq              — List DLQ entries (from MongoDB)
 *   POST   /admin/dlq/:dlqId/retry — Retry a specific failed job
 *   POST   /admin/dlq/:dlqId/resolve — Mark as resolved (no action needed)
 *   DELETE /admin/dlq/:dlqId       — Purge a specific DLQ entry (with audit)
 */

const Joi = require('joi');
const { AuditLog, DeadLetterEntry } = require('@xcg/database');
const { validate, AppError } = require('@xcg/common');
const asyncHandler = require('../utils/asyncHandler');
const logger = require('@xcg/logger').createLogger('dlq-ctrl');

const { Queue } = require('bullmq');
const { QUEUES } = require('@xcg/queue');

// ─── GET /admin/dlq ───────────────────────────────────────────────────────────

async function listDlqEntries(req, res) {
  const { status = 'pending', page = 1, limit = 50 } = req.query;
  const skip = (Math.max(1, parseInt(page, 10)) - 1) * parseInt(limit, 10);

  const filter = {};
  if (status && status !== 'all') filter.status = status;

  const [entries, total] = await Promise.all([
    DeadLetterEntry.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit, 10))
      .lean(),
    DeadLetterEntry.countDocuments(filter),
  ]);

  // Also get live Redis queue depth for real-time status
  let redisDepth = null;
  const redis = req.app.locals.redis;
  if (redis) {
    try {
      const config = require('../config').config;
      const dlqQueue = new Queue(QUEUES.DEAD_LETTER, {
        connection: { host: config.redis.host, port: config.redis.port, password: config.redis.password },
      });
      const counts = await dlqQueue.getJobCounts('waiting', 'failed', 'delayed');
      redisDepth = (counts.waiting || 0) + (counts.failed || 0) + (counts.delayed || 0);
      await dlqQueue.close().catch(() => {});
    } catch { /* Redis unavailable — DB is sufficient */ }
  }

  res.json({
    success: true,
    data: {
      total,
      entries,
      redisQueueDepth: redisDepth,
      pagination: {
        page: parseInt(page, 10),
        limit: parseInt(limit, 10),
        pages: Math.ceil(total / parseInt(limit, 10)),
      },
      alert: total > 0
        ? `⚠️ ${total} dead letter entries with status '${status}' — review immediately`
        : 'No matching dead letter entries',
    },
  });
}

// ─── POST /admin/dlq/:dlqId/retry ────────────────────────────────────────────

async function retryDlqEntry(req, res) {
  const { dlqId } = req.params;

  const entry = await DeadLetterEntry.findOne({ dlqId });
  if (!entry) throw AppError.notFound(`DLQ entry ${dlqId} not found`);
  if (entry.status === 'retried') throw AppError.conflict('This entry has already been retried');

  // Update DB record
  await DeadLetterEntry.findOneAndUpdate(
    { dlqId },
    {
      $set: {
        status:    'retried',
        retriedAt: new Date(),
        retriedBy: req.user.userId,
      },
    },
  );

  await AuditLog.create({
    actor:      req.user.userId,
    action:     'admin.dlq_retry',
    resource:   'dlq',
    resourceId: dlqId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { dlqId, sourceQueue: entry.sourceQueue },
  });

  logger.warn('DLQ: retry triggered', { dlqId, actor: req.user.userId });
  res.json({ success: true, message: `DLQ entry ${dlqId} marked as retried. Re-queue the original job manually.` });
}

// ─── POST /admin/dlq/:dlqId/resolve ──────────────────────────────────────────

async function resolveDlqEntry(req, res) {
  const { dlqId } = req.params;
  const { notes } = req.body;

  if (!notes || notes.length < 10) {
    throw AppError.badRequest('Resolution notes required (min 10 chars) — audit trail');
  }

  const entry = await DeadLetterEntry.findOne({ dlqId });
  if (!entry) throw AppError.notFound(`DLQ entry ${dlqId} not found`);

  await DeadLetterEntry.findOneAndUpdate(
    { dlqId },
    {
      $set: {
        status:          'resolved',
        resolvedAt:      new Date(),
        resolvedBy:      req.user.userId,
        resolutionNotes: notes,
      },
    },
  );

  await AuditLog.create({
    actor:      req.user.userId,
    action:     'admin.dlq_resolve',
    resource:   'dlq',
    resourceId: dlqId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { dlqId, notes },
  });

  logger.info('DLQ: entry resolved', { dlqId, actor: req.user.userId });
  res.json({ success: true, message: `DLQ entry ${dlqId} resolved.` });
}

// ─── DELETE /admin/dlq/:dlqId (purge — status update, NOT delete) ─────────────

async function purgeDlqEntry(req, res) {
  const { dlqId } = req.params;
  const { reason } = req.body;

  if (!reason || reason.length < 10) {
    throw AppError.badRequest('Must provide a reason (min 10 chars) for DLQ entry purge — audit trail required');
  }

  const entry = await DeadLetterEntry.findOne({ dlqId });
  if (!entry) throw AppError.notFound(`DLQ entry ${dlqId} not found`);

  // Mark as purged (NEVER actually delete — forensic evidence)
  await DeadLetterEntry.findOneAndUpdate(
    { dlqId },
    {
      $set: {
        status:          'purged',
        resolvedAt:      new Date(),
        resolvedBy:      req.user.userId,
        resolutionNotes: `PURGED: ${reason}`,
      },
    },
  );

  await AuditLog.create({
    actor:      req.user.userId,
    action:     'admin.dlq_purge',
    resource:   'dlq',
    resourceId: dlqId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    before:     { sourceQueue: entry.sourceQueue, error: entry.error },
    metadata:   { dlqId, reason },
  });

  logger.warn('DLQ: entry purged', { dlqId, reason, actor: req.user.userId });
  res.json({ success: true, message: `DLQ entry ${dlqId} purged. Reason logged to audit trail.` });
}

module.exports = {
  listDlqEntries:  asyncHandler(listDlqEntries),
  retryDlqEntry:   asyncHandler(retryDlqEntry),
  resolveDlqEntry: asyncHandler(resolveDlqEntry),
  purgeDlqEntry:   asyncHandler(purgeDlqEntry),
};

