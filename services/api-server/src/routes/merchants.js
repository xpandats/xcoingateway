'use strict';

const router       = require('express').Router();
const asyncHandler = require('../utils/asyncHandler');
const { authenticate }    = require('../middleware/authenticate');
const { authorize }       = require('../middleware/authorize');
const { adminIpWhitelist }= require('../middleware/adminIpWhitelist');
const {
  createMerchant, listMerchants, getMerchant,
  updateMerchant, setMerchantStatus,
  createApiKey, revokeApiKey, rotateWebhookSecret,
} = require('../controllers/merchantController');

// All routes: admin authentication + IP whitelist
router.use(authenticate, authorize('admin'), adminIpWhitelist());

router.post('/',                                 asyncHandler(createMerchant));
router.get('/',                                  asyncHandler(listMerchants));
router.get('/:id',                               asyncHandler(getMerchant));
router.put('/:id',                               asyncHandler(updateMerchant));
router.put('/:id/status',                        asyncHandler(setMerchantStatus));
router.post('/:id/api-keys',                     asyncHandler(createApiKey));
router.delete('/:id/api-keys/:keyId',            asyncHandler(revokeApiKey));
router.post('/:id/webhook-secret-rotate',        asyncHandler(rotateWebhookSecret));

module.exports = router;
