'use strict';

const router        = require('express').Router();
const asyncHandler  = require('../utils/asyncHandler');
const { authenticate }      = require('../middleware/authenticate');
const { authorize }         = require('../middleware/authorize');
const { adminIpWhitelist }  = require('../middleware/adminIpWhitelist'); // FIXED: correct export name
const {
  addWallet, listWallets, getWallet, setWalletStatus, getWalletBalance,
} = require('../controllers/walletController');

// All wallet routes: authenticate + admin role + admin IP whitelist
router.use(authenticate, authorize('admin'), adminIpWhitelist());

router.post('/',               asyncHandler(addWallet));
router.get('/',                asyncHandler(listWallets));
router.get('/:id',             asyncHandler(getWallet));
router.put('/:id/status',      asyncHandler(setWalletStatus));
router.get('/:id/balance',     asyncHandler(getWalletBalance));

module.exports = router;
