'use strict';

/**
 * @module routes/publicPay
 *
 * Public Payment Page Routes — NO authentication required.
 *
 * These routes power the customer-facing payment page.
 * Rate limited aggressively since there is no auth.
 *
 * Mounted at: /api/v1/pay
 */

const router = require('express').Router();
const rateLimit = require('express-rate-limit');
const asyncHandler = require('../utils/asyncHandler');
const {
  getPublicInvoice,
  getPublicPayStatus,
  getQrData,
} = require('../controllers/publicPayController');

// Strict rate limit — unauthenticated endpoints are prime abuse targets
const publicPayLimiter = rateLimit({
  windowMs:    60 * 1000,  // 1 minute
  max:         60,          // 60 requests per minute per IP
  standardHeaders: true,
  legacyHeaders:   false,
  message: { success: false, code: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests' },
  skip: (req) => {
    // Skip rate limit for internal health checks
    return req.headers['x-internal-check'] === process.env.INTERNAL_CHECK_SECRET;
  },
});

// Apply to all routes in this group
router.use(publicPayLimiter);

// ─── Public payment page routes ───────────────────────────────────────────────
// Order matters: specific paths before generic /:invoiceId

router.get('/:invoiceId/status',  asyncHandler(getPublicPayStatus));
router.get('/:invoiceId/qr',      asyncHandler(getQrData));
router.get('/:invoiceId',         asyncHandler(getPublicInvoice));

module.exports = router;
