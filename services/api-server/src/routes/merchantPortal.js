'use strict';

/**
 * @module routes/merchantPortal
 *
 * Merchant Self-Service Portal Routes — JWT authenticated.
 *
 * These routes are for the merchant's own dashboard app, authenticated
 * via standard JWT (login session), NOT HMAC-signed API keys.
 *
 * Security Stack:
 *   1. authenticate()       — JWT verification + revocation check
 *   2. authorize('merchant') — Must be merchant role
 *   3. All data strictly scoped to req.user's merchant profile
 *
 * Mounted at: /api/v1/merchant
 */

const router = require('express').Router();
const asyncHandler         = require('../utils/asyncHandler');
const { authenticate }     = require('../middleware/authenticate');
const { authorize }        = require('../middleware/authorize');

const {
  // Profile
  getProfile, updateProfile,
  // API Keys
  listApiKeys, createApiKey, revokeApiKey,
  // Webhook
  getWebhookConfig, updateWebhookConfig, sendTestWebhook,
  rotateWebhookSecret, listWebhookDeliveries,
  // Dashboard & Data
  getMerchantDashboard, getMerchantTransactions, getMerchantLedger,
  // Disputes
  listOwnDisputes, getOwnDispute, openDispute, respondToDispute,
} = require('../controllers/merchantPortalController');

// All portal routes require JWT + merchant role
const merchantPortalAuth = [authenticate, authorize('merchant')];
router.use(...merchantPortalAuth);

// ─── Profile ─────────────────────────────────────────────────────────────────
router.get('/profile',                  asyncHandler(getProfile));
router.put('/profile',                  asyncHandler(updateProfile));

// ─── API Keys ────────────────────────────────────────────────────────────────
router.get('/api-keys',                 asyncHandler(listApiKeys));
router.post('/api-keys',                asyncHandler(createApiKey));
router.delete('/api-keys/:keyId',       asyncHandler(revokeApiKey));

// ─── Webhook Configuration ───────────────────────────────────────────────────
// Order matters: specific paths before generic
router.get('/webhook/deliveries',       asyncHandler(listWebhookDeliveries));
router.post('/webhook/test',            asyncHandler(sendTestWebhook));
router.post('/webhook/secret-rotate',   asyncHandler(rotateWebhookSecret));
router.get('/webhook',                  asyncHandler(getWebhookConfig));
router.put('/webhook',                  asyncHandler(updateWebhookConfig));

// ─── Dashboard & Data ─────────────────────────────────────────────────────────
router.get('/dashboard',                asyncHandler(getMerchantDashboard));
router.get('/transactions',             asyncHandler(getMerchantTransactions));
router.get('/ledger',                   asyncHandler(getMerchantLedger));

// ─── Disputes ────────────────────────────────────────────────────────────────
router.get('/disputes',                 asyncHandler(listOwnDisputes));
router.post('/disputes',                asyncHandler(openDispute));
router.get('/disputes/:id',             asyncHandler(getOwnDispute));
router.post('/disputes/:id/respond',    asyncHandler(respondToDispute));

module.exports = router;
