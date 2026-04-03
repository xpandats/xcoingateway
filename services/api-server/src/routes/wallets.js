'use strict';

/**
 * @module routes/wallets
 * Wallet management routes — admin only.
 */

const router       = require('express').Router();
const asyncHandler = require('../utils/asyncHandler');
const { authenticate }  = require('../middleware/authenticate');
const { authorize }     = require('../middleware/authorize');
const { adminIpCheck }  = require('../middleware/adminIpCheck');
const {
  addWallet, listWallets, getWallet, setWalletStatus, getWalletBalance,
} = require('../controllers/walletController');

// All wallet routes: must be authenticated + admin + within admin IP whitelist
router.use(authenticate, authorize('admin'), adminIpCheck);

router.post('/',                   asyncHandler(addWallet));
router.get('/',                    asyncHandler(listWallets));
router.get('/:id',                 asyncHandler(getWallet));
router.put('/:id/status',          asyncHandler(setWalletStatus));
router.get('/:id/balance',         asyncHandler(getWalletBalance));

module.exports = router;
