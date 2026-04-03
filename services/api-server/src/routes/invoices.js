'use strict';

const router          = require('express').Router();
const merchantApiAuth = require('../middleware/merchantApiAuth');
const {
  createInvoice, getInvoice, listInvoices, getPaymentStatus,
} = require('../controllers/invoiceController');

module.exports = function (redisClient) {
  const auth = merchantApiAuth(redisClient);

  router.post('/',            auth, createInvoice);
  router.get('/',             auth, listInvoices);
  router.get('/:id',          auth, getInvoice);
  router.get('/:id/status',   auth, getPaymentStatus);   // Polling endpoint

  return router;
};
