'use strict';

const router = require('express').Router();
const asyncHandler = require('../utils/asyncHandler');
const { authenticate }     = require('../middleware/authenticate');
const { authorize }        = require('../middleware/authorize');
const { adminIpWhitelist } = require('../middleware/adminIpWhitelist');
const {
  getDashboard, listTransactions,
  listPendingWithdrawals, approveWithdrawal,
  getAuditLog, pauseWithdrawals, resumeWithdrawals,
} = require('../controllers/adminController');

// All admin routes: full auth + admin role + IP whitelist
router.use(authenticate, authorize('admin'), adminIpWhitelist());

// Dashboard
router.get('/dashboard', asyncHandler(getDashboard));

// Transactions
router.get('/transactions', asyncHandler(listTransactions));

// Withdrawal approvals
router.get('/withdrawals/pending',       asyncHandler(listPendingWithdrawals));
router.put('/withdrawals/:id/approve',   asyncHandler(approveWithdrawal));

// Audit log
router.get('/audit-log', asyncHandler(getAuditLog));

// Emergency controls (superadmin only)
router.post('/system/pause-withdrawals',  authorize('super_admin'), asyncHandler(pauseWithdrawals));
router.post('/system/resume-withdrawals', authorize('super_admin'), asyncHandler(resumeWithdrawals));

module.exports = router;
