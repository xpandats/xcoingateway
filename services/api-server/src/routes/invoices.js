'use strict';

/**
 * @module routes/invoices
 * Invoice/Payment routes — HMAC-authenticated merchant API.
 */

const router          = require('express').Router();
const asyncHandler    = require('../utils/asyncHandler');
const merchantApiAuth = require('../middleware/merchantApiAuth');
const { createInvoice, getInvoice, listInvoices } = require('../controllers/invoiceController');

// All routes require HMAC-signed merchant API auth
// redisClient is injected when app.js calls router(redisClient)
module.exports = function (redisClient) {
  const auth = merchantApiAuth(redisClient);

  router.post('/',    auth, asyncHandler(createInvoice));
  router.get('/',     auth, asyncHandler(listInvoices));
  router.get('/:id',  auth, asyncHandler(getInvoice));

  return router;
};
