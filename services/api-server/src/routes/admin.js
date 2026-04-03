'use strict';

/**
 * @module routes/admin — HARDENED
 *
 * Admin routes with full security stack:
 *   1. authenticate()         — JWT verification + revocation check
 *   2. authorize('admin')     — Role check (admin or super_admin only)
 *   3. require2FA()           — 2FA must be enabled on account
 *   4. adminIpWhitelist()     — IP must be on admin whitelist
 *
 * Critical actions additionally require:
 *   5. confirmCriticalAction  — Live TOTP code in request body
 */

const router = require('express').Router();
const asyncHandler             = require('../utils/asyncHandler');
const { authenticate }         = require('../middleware/authenticate');
const { authorize }            = require('../middleware/authorize');
const { require2FA }           = require('../middleware/require2FA');
const { adminIpWhitelist }     = require('../middleware/adminIpWhitelist');
const { confirmCriticalAction }= require('../middleware/confirmCriticalAction');
const {
  getDashboard, listTransactions,
  listPendingWithdrawals, approveWithdrawal,
  getAuditLog, pauseWithdrawals, resumeWithdrawals,
} = require('../controllers/adminController');

// ─── Full admin security stack ────────────────────────────────────────────────
// Every admin route goes through all 4 layers
const adminAuth = [authenticate, authorize('admin'), require2FA, adminIpWhitelist()];

// ─── Dashboard ───────────────────────────────────────────────────────────────
router.get('/dashboard',                    adminAuth, asyncHandler(getDashboard));

// ─── Transactions ─────────────────────────────────────────────────────────────
router.get('/transactions',                 adminAuth, asyncHandler(listTransactions));

// ─── Withdrawal Approvals ─────────────────────────────────────────────────────
router.get('/withdrawals/pending',          adminAuth, asyncHandler(listPendingWithdrawals));

// CRITICAL: Withdrawal approval requires live TOTP re-confirmation
router.put('/withdrawals/:id/approve',
  adminAuth,
  confirmCriticalAction,      // ← TOTP required in body (_totpCode)
  asyncHandler(approveWithdrawal),
);

// ─── Audit Log ────────────────────────────────────────────────────────────────
router.get('/audit-log',                    adminAuth, asyncHandler(getAuditLog));

// ─── Emergency Controls (super_admin only + TOTP) ─────────────────────────────
// Double role check: must be super_admin (not just admin)
const superAdminAuth = [authenticate, authorize('super_admin'), require2FA, adminIpWhitelist()];

router.post('/system/pause-withdrawals',
  superAdminAuth,
  confirmCriticalAction,     // ← TOTP required
  asyncHandler(pauseWithdrawals),
);

router.post('/system/resume-withdrawals',
  superAdminAuth,
  confirmCriticalAction,     // ← TOTP required
  asyncHandler(resumeWithdrawals),
);

module.exports = router;
