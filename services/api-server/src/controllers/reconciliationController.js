'use strict';

/**
 * @module controllers/reconciliationController
 *
 * Reconciliation Report Admin API.
 *
 * Provides admin visibility into reconciliation run history
 * and ability to trigger manual runs.
 *
 * Routes (mounted at /admin/reconciliation):
 *   GET  /latest               — Latest reconciliation report
 *   GET  /                     — Report history (paginated)
 *   GET  /:id                  — Specific report details
 *   POST /trigger              — Trigger manual reconciliation (TOTP)
 *   POST /:id/resolve          — Mark mismatch as resolved (TOTP)
 */

const Joi = require('joi');
const { v4: uuidv4 } = require('uuid');
const { validate, AppError, ErrorCodes } = require('@xcg/common');
const { ReconciliationReport, AuditLog } = require('@xcg/database');
const asyncHandler = require('../utils/asyncHandler');
const logger = require('@xcg/logger').createLogger('recon-ctrl');

const paginationSchema = Joi.object({
  page:   Joi.number().integer().min(1).default(1),
  limit:  Joi.number().integer().min(1).max(100).default(20),
  status: Joi.string().valid('running', 'completed', 'failed').optional(),
  passed: Joi.boolean().optional(),
}).options({ stripUnknown: true });

const resolveSchema = Joi.object({
  resolutionNotes: Joi.string().min(10).max(2000).required(),
}).options({ stripUnknown: true });

// ─── GET /admin/reconciliation/latest ────────────────────────────────────────

async function getLatestReport(req, res) {
  const report = await ReconciliationReport.findOne({ status: 'completed' })
    .sort({ completedAt: -1 })
    .lean();

  if (!report) {
    return res.json({
      success: true,
      data:    { report: null, message: 'No completed reconciliation reports yet' },
    });
  }

  res.json({ success: true, data: { report } });
}

// ─── GET /admin/reconciliation ────────────────────────────────────────────────

async function listReports(req, res) {
  const { page, limit, status, passed } = validate(paginationSchema, req.query);

  const filter = {};
  if (status !== undefined) filter.status = status;
  if (passed !== undefined) filter.passed = passed;

  const [reports, total] = await Promise.all([
    ReconciliationReport.find(filter)
      .select('-mismatches') // Omit detail array in list view
      .sort({ startedAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(),
    ReconciliationReport.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data: { reports, pagination: { page, limit, total, pages: Math.ceil(total / limit) } },
  });
}

// ─── GET /admin/reconciliation/:id ───────────────────────────────────────────

async function getReportDetail(req, res) {
  const report = await ReconciliationReport.findById(req.params.id).lean();
  if (!report) throw AppError.notFound('Reconciliation report not found', ErrorCodes.RECON_REPORT_NOT_FOUND);

  res.json({ success: true, data: { report } });
}

// ─── POST /admin/reconciliation/trigger ──────────────────────────────────────

async function triggerReconciliation(req, res) {
  // Check if one is already running
  const running = await ReconciliationReport.findOne({ status: 'running' }).lean();
  if (running) {
    throw AppError.conflict(
      'A reconciliation run is already in progress. Wait for it to complete.',
      ErrorCodes.RECON_ALREADY_RUNNING,
    );
  }

  // Create a "running" report — the reconciliation-service will pick this up via queue
  // and update the report as it progresses
  const reportId = `recon_${uuidv4().replace(/-/g, '')}`;
  const report   = await ReconciliationReport.create({
    reportId,
    triggeredBy: String(req.user._id),
    startedAt:   new Date(),
    status:      'running',
  });

  // Publish trigger event to reconciliation service via Redis
  const redis = req.app.locals.redis;
  if (redis) {
    await redis.publish('xcg:reconciliation:trigger', JSON.stringify({
      reportId,
      triggeredBy: String(req.user._id),
      manual:      true,
    }));
  }

  await AuditLog.create({
    actor:      String(req.user._id),
    action:     'reconciliation.triggered',
    resource:   'reconciliation',
    resourceId: reportId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { reportId },
  });

  logger.info('ReconCtrl: manual reconciliation triggered', {
    reportId,
    adminId: String(req.user._id),
  });

  res.status(202).json({
    success: true,
    data:    { reportId, status: 'running', message: 'Reconciliation started. Poll /admin/reconciliation/latest for results.' },
  });
}

// ─── POST /admin/reconciliation/:id/resolve ───────────────────────────────────

async function resolveReport(req, res) {
  const { resolutionNotes } = validate(resolveSchema, req.body);

  const report = await ReconciliationReport.findById(req.params.id);
  if (!report) throw AppError.notFound('Reconciliation report not found', ErrorCodes.RECON_REPORT_NOT_FOUND);

  if (report.passed) {
    throw AppError.conflict('This reconciliation report has no mismatches to resolve');
  }
  if (report.resolvedAt) {
    throw AppError.conflict('Report has already been marked as resolved');
  }

  report.resolvedAt      = new Date();
  report.resolvedBy      = req.user._id;
  report.resolutionNotes = resolutionNotes;
  await report.save();

  await AuditLog.create({
    actor:      String(req.user._id),
    action:     'reconciliation.mismatch_resolved',
    resource:   'reconciliation',
    resourceId: report.reportId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { resolutionNotes },
  });

  res.json({ success: true, data: { report } });
}

module.exports = {
  getLatestReport:      asyncHandler(getLatestReport),
  listReports:          asyncHandler(listReports),
  getReportDetail:      asyncHandler(getReportDetail),
  triggerReconciliation:asyncHandler(triggerReconciliation),
  resolveReport:        asyncHandler(resolveReport),
};
