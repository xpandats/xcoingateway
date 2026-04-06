'use strict';

const router              = require('express').Router();
const merchantApiAuth     = require('../middleware/merchantApiAuth');
const asyncHandler        = require('../utils/asyncHandler');
const {
  merchantReadLimiter, merchantWriteLimiter, merchantBurstGuard,
} = require('../middleware/merchantRateLimit');
const {
  createInvoice, getInvoice, listInvoices, getPaymentStatus, cancelInvoice,
} = require('../controllers/invoiceController');


module.exports = function (redisClient) {
  const auth = merchantApiAuth(redisClient);

  // Write: create invoice
  //   Layer 1 — burst guard: max 20 invoice creates in any 60-second window
  //   Layer 2 — write limiter: max 60 writes per 15 minutes (shared write budget)
  //   Rationale: prevents burst flooding of the invoice slot reservation path
  //   (each create does a Redis NX slot check + MongoDB collision check).
  router.post('/',
    auth,
    merchantBurstGuard(20, 60, 'invoice'),
    merchantWriteLimiter,
    asyncHandler(createInvoice),
  );

  // Reads: list / get / status — read rate limit
  router.get('/',             auth, merchantReadLimiter,  asyncHandler(listInvoices));
  router.get('/:id/status',   auth, merchantReadLimiter,  asyncHandler(getPaymentStatus));
  router.get('/:id',          auth, merchantReadLimiter,  asyncHandler(getInvoice));

  // Cancel invoice (merchant-initiated) — write limit
  router.delete('/:id',       auth, merchantWriteLimiter, asyncHandler(cancelInvoice));

  return router;
};

