'use strict';

const router          = require('express').Router();
const merchantApiAuth = require('../middleware/merchantApiAuth');
const { merchantReadLimiter, merchantWriteLimiter } = require('../middleware/merchantRateLimit');
const { createWithdrawal, listWithdrawals, getWithdrawal, getBalance } = require('../controllers/withdrawalController');

module.exports = function (redisClient) {
  const auth = merchantApiAuth(redisClient);

  // POST: withdrawal request — strict write limit
  router.post('/',        auth, merchantWriteLimiter, createWithdrawal);

  // GET: list / status — read limit
  router.get('/',         auth, merchantReadLimiter,  listWithdrawals);
  router.get('/balance',  auth, merchantReadLimiter,  getBalance);    // Before /:id
  router.get('/:id',      auth, merchantReadLimiter,  getWithdrawal);

  return router;
};
