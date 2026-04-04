'use strict';

/**
 * @module routes/merchants — HARDENED
 *
 * Admin merchant management routes.
 * Full 4-layer security: JWT + role + 2FA + IP whitelist.
 */

const router = require('express').Router();
const asyncHandler             = require('../utils/asyncHandler');
const { authenticate }         = require('../middleware/authenticate');
const { authorize }            = require('../middleware/authorize');
const { require2FA }           = require('../middleware/require2FA');
const { adminIpWhitelist }     = require('../middleware/adminIpWhitelist');
const { confirmCriticalAction }= require('../middleware/confirmCriticalAction');
const {
  createMerchant, listMerchants, getMerchant,
  updateMerchant, setMerchantStatus,
  createApiKey, revokeApiKey, rotateWebhookSecret,
  approveMerchant, suspendMerchant,
  getMerchantTransactions, getMerchantLedger, getMerchantInvoices, getMerchantStats,
  setMerchantFees, setMerchantLimits,
} = require('../controllers/merchantController');

// Full admin security stack on every merchant admin route
const adminAuth = [authenticate, authorize('admin'), require2FA, adminIpWhitelist()];

// ─── CRUD ─────────────────────────────────────────────────────────────────────
router.post('/',                          adminAuth, asyncHandler(createMerchant));
router.get('/',                           adminAuth, asyncHandler(listMerchants));
router.get('/:id',                        adminAuth, asyncHandler(getMerchant));
router.put('/:id',                        adminAuth, asyncHandler(updateMerchant));

// Status change = critical action (deactivating a merchant stops all payments)
router.put('/:id/status',                 adminAuth, confirmCriticalAction, asyncHandler(setMerchantStatus));

// ─── Approval Workflow ────────────────────────────────────────────────────────
// Approve or reject a pending merchant (TOTP required — unlocks payment capability)
router.post('/:id/approve',               adminAuth, confirmCriticalAction, asyncHandler(approveMerchant));
// Suspend: immediately stops all merchant activity (TOTP required)
router.post('/:id/suspend',               adminAuth, confirmCriticalAction, asyncHandler(suspendMerchant));

// ─── Per-Merchant Data Views ──────────────────────────────────────────────────
router.get('/:id/transactions',           adminAuth, asyncHandler(getMerchantTransactions));
router.get('/:id/ledger',                 adminAuth, asyncHandler(getMerchantLedger));
router.get('/:id/invoices',               adminAuth, asyncHandler(getMerchantInvoices));
router.get('/:id/stats',                  adminAuth, asyncHandler(getMerchantStats));

// ─── Fee & Limit Configuration ────────────────────────────────────────────────
// Fee changes directly impact merchant revenue — TOTP required
router.put('/:id/fees',                   adminAuth, confirmCriticalAction, asyncHandler(setMerchantFees));
router.put('/:id/limits',                 adminAuth, confirmCriticalAction, asyncHandler(setMerchantLimits));

// ─── API Key Operations ───────────────────────────────────────────────────────
router.post('/:id/api-keys',              adminAuth, asyncHandler(createApiKey));
router.delete('/:id/api-keys/:keyId',     adminAuth, confirmCriticalAction, asyncHandler(revokeApiKey));

// ─── Webhook Secret Rotation ──────────────────────────────────────────────────
router.post('/:id/webhook-secret-rotate', adminAuth, asyncHandler(rotateWebhookSecret));

module.exports = router;
