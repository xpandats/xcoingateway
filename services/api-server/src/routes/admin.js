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
  getTransactionDetail,
  listAllInvoices, getInvoiceDetail, adminCancelInvoice,
} = require('../controllers/adminController');
const {
  openDispute, resolveDispute, listDisputes, getDispute,
} = require('../controllers/disputeController');
const {
  listBlacklist, addToBlacklist, removeFromBlacklist,
  listFraudEvents, getFraudStats,
} = require('../controllers/fraudController');

// ─── Full admin security stack ────────────────────────────────────────────────
// Every admin route goes through all 4 layers
const adminAuth = [authenticate, authorize('admin'), require2FA, adminIpWhitelist()];

// ─── Dashboard ───────────────────────────────────────────────────────────────
router.get('/dashboard',                    adminAuth, asyncHandler(getDashboard));

// ─── Transactions ────────────────────────────────────────────────────────────
router.get('/transactions',                 adminAuth, asyncHandler(listTransactions));
router.get('/transactions/:id',             adminAuth, asyncHandler(getTransactionDetail));

// ─── Invoices ───────────────────────────────────────────────────────────────
router.get('/invoices',                     adminAuth, asyncHandler(listAllInvoices));
router.get('/invoices/:id',                 adminAuth, asyncHandler(getInvoiceDetail));
// Admin cancel requires TOTP — cancelling an invoice stops customer payment
router.post('/invoices/:id/cancel',
  adminAuth,
  confirmCriticalAction,
  asyncHandler(adminCancelInvoice),
);

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

// ─── Dispute Management ───────────────────────────────────────────────────────
// List + get: read-only, standard admin auth
router.get('/disputes',                     adminAuth, asyncHandler(listDisputes));
router.get('/disputes/:id',                 adminAuth, asyncHandler(getDispute));

// Open dispute: freezes merchant funds atomically
router.post('/disputes',
  adminAuth,
  asyncHandler(openDispute),
);

// CRITICAL: Resolve dispute releases or redirects frozen funds
router.post('/disputes/:id/resolve',
  adminAuth,
  confirmCriticalAction,     // ← TOTP required — releasing frozen funds is critical
  asyncHandler(resolveDispute),
);

// ─── Fraud & Risk Management ──────────────────────────────────────────────────
// Blacklist: read + add
router.get('/fraud/blacklist',              adminAuth, asyncHandler(listBlacklist));
router.post('/fraud/blacklist',
  adminAuth,
  confirmCriticalAction,     // ← TOTP required — blacklisting is an irreversible action
  asyncHandler(addToBlacklist),
);
// Blacklist: remove (deactivate only — never delete, audit trail preserved)
router.delete('/fraud/blacklist/:id',
  adminAuth,
  confirmCriticalAction,     // ← TOTP required
  asyncHandler(removeFromBlacklist),
);

// Fraud event log — read only
router.get('/fraud/events',                 adminAuth, asyncHandler(listFraudEvents));
router.get('/fraud/stats',                  adminAuth, asyncHandler(getFraudStats));

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

// ─── Audit Chain Integrity (#2 mainnet requirement) ───────────────────────────
// Verify the cryptographic hash chain of the audit log.
// Super-admin only — a broken chain is a security incident.
const { verifyAuditChain, getAuditChainStatus } = require('../controllers/auditChainController');

router.get('/audit-chain/status',  superAdminAuth, asyncHandler(getAuditChainStatus));
router.post('/audit-chain/verify',
  superAdminAuth,
  confirmCriticalAction,     // ← TOTP required — chain verification reveals audit state
  asyncHandler(verifyAuditChain),
);

// ─── OFAC Sync (#3 mainnet requirement) ──────────────────────────────────────
// Manually trigger OFAC sanctions list sync.
// Automated daily sync is handled by the compliance service cron job.
const { triggerOfacSync, getOfacSyncStatus } = require('../controllers/ofacController');

router.get('/compliance/ofac/status',   superAdminAuth, asyncHandler(getOfacSyncStatus));
router.post('/compliance/ofac/sync',
  superAdminAuth,
  confirmCriticalAction,     // ← TOTP required — syncing OFAC affects all blacklists
  asyncHandler(triggerOfacSync),
);

// ─── Dead Letter Queue (#4 mainnet requirement) ───────────────────────────────
// Monitor and retry failed queue messages.
const { listDlqEntries, retryDlqEntry, purgeDlqEntry } = require('../controllers/dlqController');

router.get('/dlq',                      superAdminAuth, asyncHandler(listDlqEntries));
router.post('/dlq/:jobId/retry',
  superAdminAuth,
  confirmCriticalAction,
  asyncHandler(retryDlqEntry),
);
router.delete('/dlq/:jobId',
  superAdminAuth,
  confirmCriticalAction,
  asyncHandler(purgeDlqEntry),
);

module.exports = router;
