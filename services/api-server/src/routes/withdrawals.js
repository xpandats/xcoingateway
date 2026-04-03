'use strict';

const router          = require('express').Router();
const merchantApiAuth = require('../middleware/merchantApiAuth');
const { createWithdrawal, listWithdrawals, getWithdrawal, getBalance } = require('../controllers/withdrawalController');

module.exports = function (redisClient) {
  const auth = merchantApiAuth(redisClient);

  router.post('/',    auth, createWithdrawal);
  router.get('/',     auth, listWithdrawals);
  router.get('/balance', auth, getBalance);     // Must be before /:id
  router.get('/:id',  auth, getWithdrawal);

  return router;
};
