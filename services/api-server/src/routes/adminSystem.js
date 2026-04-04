'use strict';

/**
 * @module routes/adminSystem
 *
 * Admin System Configuration & Emergency Controls.
 *
 * Security: authenticate + authorize('admin') + require2FA + adminIpWhitelist
 * Critical mutations: require TOTP via confirmCriticalAction
 *
 * Mounted at: /admin/system
 */

const router = require('express').Router();
const asyncHandler             = require('../utils/asyncHandler');
const { authenticate }         = require('../middleware/authenticate');
const { authorize }            = require('../middleware/authorize');
const { require2FA }           = require('../middleware/require2FA');
const { adminIpWhitelist }     = require('../middleware/adminIpWhitelist');
const { confirmCriticalAction }= require('../middleware/confirmCriticalAction');
const {
  getSystemConfig, updateSystemConfig, getSystemHealth, getSystemStats,
  pauseInvoices, resumeInvoices, pauseWithdrawals, resumeWithdrawals,
} = require('../controllers/systemController');

const adminAuth      = [authenticate, authorize('admin'),       require2FA, adminIpWhitelist()];
const superAdminAuth = [authenticate, authorize('super_admin'), require2FA, adminIpWhitelist()];

// ─── Read operations (all admins) ─────────────────────────────────────────────
router.get('/config',         adminAuth, asyncHandler(getSystemConfig));
router.get('/health',         adminAuth, asyncHandler(getSystemHealth));
router.get('/stats',          adminAuth, asyncHandler(getSystemStats));

// ─── Config update (TOTP required) ───────────────────────────────────────────
router.put('/config/:key',
  adminAuth,
  confirmCriticalAction,
  asyncHandler(updateSystemConfig),
);

// ─── Emergency controls (super_admin + TOTP) ──────────────────────────────────
router.post('/pause-invoices',
  superAdminAuth,
  confirmCriticalAction,
  asyncHandler(pauseInvoices),
);
router.post('/resume-invoices',
  superAdminAuth,
  confirmCriticalAction,
  asyncHandler(resumeInvoices),
);
router.post('/pause-withdrawals',
  superAdminAuth,
  confirmCriticalAction,
  asyncHandler(pauseWithdrawals),
);
router.post('/resume-withdrawals',
  superAdminAuth,
  confirmCriticalAction,
  asyncHandler(resumeWithdrawals),
);

module.exports = router;
