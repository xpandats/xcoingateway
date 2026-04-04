'use strict';

/**
 * @module routes/adminWebhooks
 *
 * Admin Webhook Delivery Monitoring Routes.
 *
 * Security: authenticate + authorize('admin') + require2FA + adminIpWhitelist
 * Retry: requires TOTP
 *
 * Mounted at: /admin/webhooks
 */

const router = require('express').Router();
const asyncHandler             = require('../utils/asyncHandler');
const { authenticate }         = require('../middleware/authenticate');
const { authorize }            = require('../middleware/authorize');
const { require2FA }           = require('../middleware/require2FA');
const { adminIpWhitelist }     = require('../middleware/adminIpWhitelist');
const { confirmCriticalAction }= require('../middleware/confirmCriticalAction');
const {
  listDeliveries, listFailedDeliveries, getDelivery, retryDelivery,
} = require('../controllers/webhookMonitorController');

const adminAuth = [authenticate, authorize('admin'), require2FA, adminIpWhitelist()];

// ─── Read operations ──────────────────────────────────────────────────────────
router.get('/deliveries/failed', adminAuth, asyncHandler(listFailedDeliveries)); // Before /:id
router.get('/deliveries/:id',    adminAuth, asyncHandler(getDelivery));
router.get('/deliveries',        adminAuth, asyncHandler(listDeliveries));

// ─── Retry (TOTP required — triggers outbound HTTP) ──────────────────────────
router.post('/deliveries/:id/retry',
  adminAuth,
  confirmCriticalAction,
  asyncHandler(retryDelivery),
);

module.exports = router;
