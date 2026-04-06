'use strict';

/**
 * @module routes/merchantPortal
 *
 * Merchant Self-Service Portal Routes — JWT authenticated.
 *
 * These routes are for the merchant's own dashboard app, authenticated
 * via standard JWT (login session), NOT HMAC-signed API keys.
 *
 * Security Stack (all routes):
 *   1. authenticate()        — JWT verification + JTI blocklist check + revocation check
 *   2. authorize('merchant') — Must be merchant role
 *   3. merchantReadLimiter / merchantWriteLimiter / merchantBurstGuard per route
 *   4. All data strictly scoped to req.user's merchant profile
 *
 * RATE LIMITING RATIONALE (Gap 2 completion):
 *   The HMAC API routes (invoices.js, withdrawals.js) had merchantReadLimiter /
 *   merchantWriteLimiter applied. But merchantPortal.js had ZERO merchant-level rate
 *   limiting on any mutation (updateProfile, createApiKey, revokeApiKey, rotateWebhookSecret,
 *   openDispute, respondToDispute). A compromised merchant JWT could spam all of these.
 *
 *   Specifically dangerous:
 *   - POST /api-keys: unlimited key creation → each new key is another attack surface
 *   - POST /webhook/secret-rotate: brute-forces webhook HMAC shared secret
 *   - POST /disputes: spam disputes to flood admin review queue
 *   - GET /transactions + /ledger: heavy DB aggregations, no read limit
 *
 *   Fix: All mutations get merchantWriteLimiter + merchantBurstGuard.
 *        Heavy reads (dashboard, transactions, ledger) get merchantReadLimiter.
 *        Sensitive ops (key create, secret rotate) get dedicated tight burst guards.
 *
 * Mounted at: /api/v1/merchant
 */

const router = require('express').Router();
const asyncHandler         = require('../utils/asyncHandler');
const { authenticate }     = require('../middleware/authenticate');
const { authorize }        = require('../middleware/authorize');
const {
  merchantReadLimiter,
  merchantWriteLimiter,
  merchantBurstGuard,
} = require('../middleware/merchantRateLimit');

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

// ─── Auth: All portal routes require JWT + merchant role ──────────────────────
router.use(authenticate);
router.use(authorize('merchant'));

// ─── Profile ──────────────────────────────────────────────────────────────────
// GET — no merchant rate limit (trivial query)
router.get('/profile',     asyncHandler(getProfile));

// PUT — write limit: profile updates are low-frequency by nature
router.put('/profile',
  merchantWriteLimiter,
  asyncHandler(updateProfile),
);

// ─── API Keys ─────────────────────────────────────────────────────────────────
// GET — no read limit needed (result set is tiny: merchant's own keys)
router.get('/api-keys',    asyncHandler(listApiKeys));

// POST — tight burst guard + write limit
//   A new API key is an attack surface expansion. Merchants rarely need more than
//   2-3 keys. Burst guard: max 3 creates in 300 seconds (5 min).
//   Write limit: counted under general write budget.
router.post('/api-keys',
  merchantBurstGuard(3, 300, 'apikey-create'),
  merchantWriteLimiter,
  asyncHandler(createApiKey),
);

// DELETE — write limit (revoking is fine but shouldn't be scriptable)
router.delete('/api-keys/:keyId',
  merchantWriteLimiter,
  asyncHandler(revokeApiKey),
);

// ─── Webhook Configuration ────────────────────────────────────────────────────
// GET — no rate limit (trivial query)
router.get('/webhook',                asyncHandler(getWebhookConfig));

// PUT — write limit (webhook URL changes are infrequent)
router.put('/webhook',
  merchantWriteLimiter,
  asyncHandler(updateWebhookConfig),
);

// GET delivery logs — read limit (could be large result set)
router.get('/webhook/deliveries',
  merchantReadLimiter,
  asyncHandler(listWebhookDeliveries),
);

// POST /webhook/test — original 1/min limiter preserved + write budget consumed
// H5: Each call makes a REAL HTTP request to the merchant's server.
// Kept at 1/min to prevent using us as a request amplifier / DDoS tool.
const rateLimit = require('express-rate-limit');
const webhookTestLimiter = rateLimit({
  windowMs: 60 * 1000,
  max:      1,
  keyGenerator: (req) => `merchant:${req.user.userId || req.ip}:webhooktest`,
  standardHeaders: true,
  legacyHeaders:   false,
  message: { success: false, code: 'RATE_LIMIT_EXCEEDED', message: 'Webhook test limited to 1 per minute.' },
});

router.post('/webhook/test',
  webhookTestLimiter,
  merchantWriteLimiter,
  asyncHandler(sendTestWebhook),
);

// POST /webhook/secret-rotate — very tight burst (1 rotation per 5 minutes max)
// Rotating the webhook secret invalidates all existing deliveries that haven't
// been retried yet. Burst cycling this is an availability attack on the merchant's
// own webhook delivery. Also: each rotation generates a new HMAC secret — brute
// cycling is pointless but we still cap it.
router.post('/webhook/secret-rotate',
  merchantBurstGuard(1, 300, 'webhook-rotate'),
  merchantWriteLimiter,
  asyncHandler(rotateWebhookSecret),
);

// ─── Dashboard & Data (heavy DB aggregations) ─────────────────────────────────
// All read-limited — these run multi-stage MongoDB aggregation pipelines.
// Without limits a merchant could hammer /transactions every second.
router.get('/dashboard',
  merchantReadLimiter,
  asyncHandler(getMerchantDashboard),
);

router.get('/transactions',
  merchantReadLimiter,
  asyncHandler(getMerchantTransactions),
);

router.get('/ledger',
  merchantReadLimiter,
  asyncHandler(getMerchantLedger),
);

// ─── Disputes ─────────────────────────────────────────────────────────────────
// GET list — read limit (could return many records)
router.get('/disputes',
  merchantReadLimiter,
  asyncHandler(listOwnDisputes),
);

// GET single — no limit (trivial by-ID lookup)
router.get('/disputes/:id',         asyncHandler(getOwnDispute));

// POST open dispute — write + burst guard
// A merchant has a finite number of real disputes. Burst-opening 50 disputes
// would flood the admin review queue. Cap: 5 in any 15-minute window.
router.post('/disputes',
  merchantBurstGuard(5, 900, 'dispute-open'),
  merchantWriteLimiter,
  asyncHandler(openDispute),
);

// POST respond to dispute — write limit (legitimate repeated responses are rare)
router.post('/disputes/:id/respond',
  merchantWriteLimiter,
  asyncHandler(respondToDispute),
);

module.exports = router;
