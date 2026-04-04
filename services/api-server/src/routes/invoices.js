'use strict';

const router              = require('express').Router();
const merchantApiAuth     = require('../middleware/merchantApiAuth');
const asyncHandler        = require('../utils/asyncHandler');
const { merchantReadLimiter, merchantWriteLimiter } = require('../middleware/merchantRateLimit');
const {
  createInvoice, getInvoice, listInvoices, getPaymentStatus, cancelInvoice,
} = require('../controllers/invoiceController');

module.exports = function (redisClient) {
  const auth = merchantApiAuth(redisClient);

  // Write: create invoice — write rate limit applied AFTER auth (merchantId known)
  router.post('/',            auth, merchantWriteLimiter, asyncHandler(createInvoice));

  // Reads: list / get / status — read rate limit
  router.get('/',             auth, merchantReadLimiter,  asyncHandler(listInvoices));
  router.get('/:id/status',   auth, merchantReadLimiter,  asyncHandler(getPaymentStatus));  // Before /:id
  router.get('/:id',          auth, merchantReadLimiter,  asyncHandler(getInvoice));

  // Cancel invoice (merchant-initiated)
  router.delete('/:id',       auth, merchantWriteLimiter, asyncHandler(cancelInvoice));

  return router;
};
