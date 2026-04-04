'use strict';

/**
 * @module routes/adminReconciliation
 *
 * Admin Reconciliation Report Routes.
 *
 * Security: authenticate + authorize('admin') + require2FA + adminIpWhitelist
 * Manual trigger + resolve: require TOTP
 *
 * Mounted at: /admin/reconciliation
 */

const router = require('express').Router();
const asyncHandler             = require('../utils/asyncHandler');
const { authenticate }         = require('../middleware/authenticate');
const { authorize }            = require('../middleware/authorize');
const { require2FA }           = require('../middleware/require2FA');
const { adminIpWhitelist }     = require('../middleware/adminIpWhitelist');
const { confirmCriticalAction }= require('../middleware/confirmCriticalAction');
const {
  getLatestReport, listReports, getReportDetail,
  triggerReconciliation, resolveReport,
} = require('../controllers/reconciliationController');

const adminAuth = [authenticate, authorize('admin'), require2FA, adminIpWhitelist()];

// ─── Read operations ──────────────────────────────────────────────────────────
router.get('/latest',     adminAuth, asyncHandler(getLatestReport));
router.get('/',           adminAuth, asyncHandler(listReports));
router.get('/:id',        adminAuth, asyncHandler(getReportDetail));

// ─── Manual trigger (TOTP required — impacts system state) ───────────────────
router.post('/trigger',
  adminAuth,
  confirmCriticalAction,
  asyncHandler(triggerReconciliation),
);

// ─── Resolve mismatch (TOTP required — audit action) ─────────────────────────
router.post('/:id/resolve',
  adminAuth,
  confirmCriticalAction,
  asyncHandler(resolveReport),
);

module.exports = router;
