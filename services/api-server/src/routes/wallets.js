'use strict';

/**
 * @module routes/wallets — HARDENED
 *
 * Admin wallet management routes.
 * Full 4-layer security: JWT + role + 2FA + IP whitelist.
 * Wallet operations are highest-sensitivity — private key storage.
 */

const router = require('express').Router();
const asyncHandler             = require('../utils/asyncHandler');
const { authenticate }         = require('../middleware/authenticate');
const { authorize }            = require('../middleware/authorize');
const { require2FA }           = require('../middleware/require2FA');
const { adminIpWhitelist }     = require('../middleware/adminIpWhitelist');
const { confirmCriticalAction }= require('../middleware/confirmCriticalAction');
const {
  addWallet, listWallets, getWallet, setWalletStatus, getWalletBalance,
} = require('../controllers/walletController');

// Full admin security stack — wallets are Zone 2/3 sensitive
const adminAuth = [authenticate, authorize('admin'), require2FA, adminIpWhitelist()];

// Adding a wallet (imports private key) = ALWAYS requires TOTP
router.post('/',               adminAuth, confirmCriticalAction, asyncHandler(addWallet));

// Read operations
router.get('/',                adminAuth, asyncHandler(listWallets));
router.get('/:id',             adminAuth, asyncHandler(getWallet));
router.get('/:id/balance',     adminAuth, asyncHandler(getWalletBalance));

// Status change = critical (disabling stops all payments)
router.put('/:id/status',      adminAuth, confirmCriticalAction, asyncHandler(setWalletStatus));

module.exports = router;
