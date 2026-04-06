'use strict';

const router          = require('express').Router();
const merchantApiAuth = require('../middleware/merchantApiAuth');
const {
  merchantReadLimiter, merchantWithdrawalLimiter, merchantBurstGuard,
} = require('../middleware/merchantRateLimit');
const { createWithdrawal, listWithdrawals, getWithdrawal, getBalance } = require('../controllers/withdrawalController');


module.exports = function (redisClient) {
  const auth = merchantApiAuth(redisClient);

  // POST: withdrawal request
  //   Layer 1: merchantBurstGuard  — max 5 in any 60-second window (burst cap)
  //   Layer 2: merchantWithdrawalLimiter — max 5 per 15 minutes (sustained cap)
  //   Rationale: separate from general write limiter so invoice traffic cannot
  //   exhaust the withdrawal budget or vice versa.
  router.post('/',
    auth,
    merchantBurstGuard(5, 60, 'withdrawal'),
    merchantWithdrawalLimiter,
    createWithdrawal,
  );

  // GET: list / status — read limit
  router.get('/',         auth, merchantReadLimiter,  listWithdrawals);
  router.get('/balance',  auth, merchantReadLimiter,  getBalance);
  router.get('/:id',      auth, merchantReadLimiter,  getWithdrawal);

  return router;
};

