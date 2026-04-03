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
} = require('../controllers/merchantController');

// Full admin security stack on every merchant admin route
const adminAuth = [authenticate, authorize('admin'), require2FA, adminIpWhitelist()];

router.post('/',                          adminAuth, asyncHandler(createMerchant));
router.get('/',                           adminAuth, asyncHandler(listMerchants));
router.get('/:id',                        adminAuth, asyncHandler(getMerchant));
router.put('/:id',                        adminAuth, asyncHandler(updateMerchant));

// Status change = critical action (deactivating a merchant stops all payments)
router.put('/:id/status',                 adminAuth, confirmCriticalAction, asyncHandler(setMerchantStatus));

// API key operations
router.post('/:id/api-keys',              adminAuth, asyncHandler(createApiKey));
router.delete('/:id/api-keys/:keyId',     adminAuth, confirmCriticalAction, asyncHandler(revokeApiKey));

// Webhook secret rotation
router.post('/:id/webhook-secret-rotate', adminAuth, asyncHandler(rotateWebhookSecret));

module.exports = router;
