'use strict';

/**
 * @module controllers/dlqController
 *
 * Dead Letter Queue (DLQ) Monitor — Mainnet Requirement #4.
 *
 * The DLQ (xcg:dead:letter) receives messages that:
 *   1. Failed HMAC signature verification (security rejection)
 *   2. Exhausted all retry attempts (5 retries with exponential backoff)
 *
 * CRITICAL: DLQ entries must be monitored. A payment that ends up in the DLQ
 * means money moved on-chain but the system failed to process it internally.
 * Without this view, funds are silently lost from tracking.
 *
 * Routes (super_admin + TOTP for mutations):
 *   GET    /admin/dlq              — List DLQ entries
 *   POST   /admin/dlq/:jobId/retry — Retry a specific failed job
 *   DELETE /admin/dlq/:jobId       — Purge a specific DLQ entry (with audit)
 */

const Joi = require('joi');
const { AuditLog }   = require('@xcg/database');
const { validate, AppError } = require('@xcg/common');
const asyncHandler = require('../utils/asyncHandler');
const logger = require('@xcg/logger').createLogger('dlq-ctrl');

const { Queue, QueueEvents } = require('bullmq');
const { QUEUES } = require('@xcg/queue');

// ─── GET /admin/dlq ───────────────────────────────────────────────────────────

async function listDlqEntries(req, res) {
  const redis = req.app.locals.redis;
  if (!redis) {
    return res.json({ success: true, data: { entries: [], total: 0, message: 'Redis not connected' } });
  }

  const config = require('../config').config;
  const dlqQueue = new Queue(QUEUES.DEAD_LETTER, {
    connection: { host: config.redis.host, port: config.redis.port, password: config.redis.password },
  });

  try {
    const [failed, completed, waiting] = await Promise.all([
      dlqQueue.getFailed(0, 99),
      dlqQueue.getCompleted(0, 20),
      dlqQueue.getWaiting(0, 99),
    ]);

    const toEntry = (job, state) => ({
      jobId:          job.id,
      state,
      originalQueue:  job.data?.original?.queueName || 'unknown',
      failureReason:  job.data?.reason             || 'unknown',
      failedAt:       job.finishedOn ? new Date(job.finishedOn) : null,
      attempts:       job.attemptsMade,
      data:           job.data,
    });

    const allEntries = [
      ...failed.map((j) => toEntry(j, 'failed')),
      ...waiting.map((j) => toEntry(j, 'waiting')),
    ];

    res.json({
      success: true,
      data: {
        total:   allEntries.length,
        entries: allEntries,
        summary: {
          failed:  failed.length,
          waiting: waiting.length,
        },
        alert: allEntries.length > 0
          ? `⚠️ ${allEntries.length} messages in dead letter queue — review immediately`
          : 'Dead letter queue is empty — no failed messages',
      },
    });
  } finally {
    await dlqQueue.close().catch(() => {});
  }
}

// ─── POST /admin/dlq/:jobId/retry ────────────────────────────────────────────

async function retryDlqEntry(req, res) {
  const { jobId } = req.params;
  const redis = req.app.locals.redis;
  if (!redis) throw AppError.serviceUnavailable('Redis not connected');

  const config = require('../config').config;
  const dlqQueue = new Queue(QUEUES.DEAD_LETTER, {
    connection: { host: config.redis.host, port: config.redis.port, password: config.redis.password },
  });

  try {
    const job = await dlqQueue.getJob(jobId);
    if (!job) throw AppError.notFound(`DLQ entry ${jobId} not found`);

    await job.retry();

    await AuditLog.create({
      actor:      req.user.userId,
      action:     'admin.dlq_retry',
      resource:   'dlq',
      resourceId: jobId,
      ipAddress:  req.ip,
      outcome:    'success',
      timestamp:  new Date(),
      metadata:   { jobId, originalQueue: job.data?.original?.queueName },
    });

    logger.warn('DLQ: retry triggered', { jobId, actor: req.user.userId });

    res.json({ success: true, message: `DLQ entry ${jobId} requeued for retry` });
  } finally {
    await dlqQueue.close().catch(() => {});
  }
}

// ─── DELETE /admin/dlq/:jobId ─────────────────────────────────────────────────

async function purgeDlqEntry(req, res) {
  const { jobId } = req.params;
  const { reason } = req.body;
  const redis = req.app.locals.redis;
  if (!redis) throw AppError.serviceUnavailable('Redis not connected');

  if (!reason || reason.length < 10) {
    throw AppError.badRequest('Must provide a reason (min 10 chars) for DLQ entry purge — audit trail required');
  }

  const config = require('../config').config;
  const dlqQueue = new Queue(QUEUES.DEAD_LETTER, {
    connection: { host: config.redis.host, port: config.redis.port, password: config.redis.password },
  });

  try {
    const job = await dlqQueue.getJob(jobId);
    if (!job) throw AppError.notFound(`DLQ entry ${jobId} not found`);

    const jobData = { ...job.data }; // Capture before removal

    await job.remove();

    await AuditLog.create({
      actor:      req.user.userId,
      action:     'admin.dlq_purge',
      resource:   'dlq',
      resourceId: jobId,
      ipAddress:  req.ip,
      outcome:    'success',
      timestamp:  new Date(),
      before:     jobData,
      metadata:   { jobId, reason },
    });

    logger.warn('DLQ: entry purged', { jobId, reason, actor: req.user.userId });

    res.json({ success: true, message: `DLQ entry ${jobId} purged. Reason logged to audit trail.` });
  } finally {
    await dlqQueue.close().catch(() => {});
  }
}

module.exports = {
  listDlqEntries: asyncHandler(listDlqEntries),
  retryDlqEntry:  asyncHandler(retryDlqEntry),
  purgeDlqEntry:  asyncHandler(purgeDlqEntry),
};
