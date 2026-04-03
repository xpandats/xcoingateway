'use strict';

const router              = require('express').Router();
const merchantApiAuth     = require('../middleware/merchantApiAuth');
const { merchantReadLimiter, merchantWriteLimiter } = require('../middleware/merchantRateLimit');
const {
  createInvoice, getInvoice, listInvoices, getPaymentStatus,
} = require('../controllers/invoiceController');

module.exports = function (redisClient) {
  const auth = merchantApiAuth(redisClient);

  // Write: create invoice — write rate limit applied AFTER auth (merchantId known)
  router.post('/',            auth, merchantWriteLimiter, createInvoice);

  // Reads: list / get / status — read rate limit
  router.get('/',             auth, merchantReadLimiter,  listInvoices);
  router.get('/:id/status',   auth, merchantReadLimiter,  getPaymentStatus);  // Before /:id
  router.get('/:id',          auth, merchantReadLimiter,  getInvoice);

  return router;
};
