'use strict';

/**
 * @module controllers/walletController — FIXED
 *
 * All admin-only wallet endpoints.
 * All actions require: authenticate + authorize('admin') + adminIpWhitelist
 */

const Joi         = require('joi');
const { validate, AppError } = require('@xcg/common');
const { config }  = require('../config');
const asyncHandler = require('../utils/asyncHandler');
const WalletService = require('../services/walletService');
const { Wallet }    = require('@xcg/database');
const { TronAdapter } = require('@xcg/tron');

const logger = require('@xcg/logger').createLogger('wallet-ctrl');

// Lazy-init singletons
let _walletService, _tronAdapter;

function getWalletService() {
  if (!_walletService) {
    _walletService = new WalletService({ logger });
  }
  return _walletService;
}

function getTronAdapter() {
  if (!_tronAdapter) {
    _tronAdapter = new TronAdapter(
      { network: config.tron.network, apiKey: config.tron.apiKey },
      logger,
    );
  }
  return _tronAdapter;
}

// ─── Validation Schemas ──────────────────────────────────────────────────────

const addWalletSchema = Joi.object({
  address:    Joi.string().pattern(/^T[1-9A-HJ-NP-Za-km-z]{33}$/).required(),
  privateKey: Joi.string().hex().length(64).required(),  // 32 bytes hex
  label:      Joi.string().trim().max(50).optional().allow(''),
  network:    Joi.string().valid('tron').default('tron'),
}).options({ stripUnknown: true });

const statusSchema = Joi.object({
  isActive: Joi.boolean().required(),
}).options({ stripUnknown: true });

// ─── Handlers ────────────────────────────────────────────────────────────────

async function addWallet(req, res) {
  const data = validate(addWalletSchema, req.body);

  const wallet = await getWalletService().addWallet(data, {
    userId: req.user._id,
    ip:     req.ip,
  });

  res.status(201).json({ success: true, data: { wallet } });
}

async function listWallets(req, res) {
  const wallets = await getWalletService().listWallets(req.query);
  res.json({ success: true, data: { wallets, count: wallets.length } });
}

async function getWallet(req, res) {
  const wallet = await Wallet.findById(req.params.id)
    .select('-encryptedPrivateKey -derivationSalt')
    .lean();
  if (!wallet) throw AppError.notFound('Wallet not found');
  res.json({ success: true, data: { wallet } });
}

async function setWalletStatus(req, res) {
  const { isActive } = validate(statusSchema, req.body);
  const wallet = await getWalletService().setWalletStatus(req.params.id, isActive, {
    userId: req.user._id,
    ip:     req.ip,
  });
  res.json({ success: true, data: { wallet } });
}

async function getWalletBalance(req, res) {
  const balance = await getWalletService().getWalletBalance(req.params.id, getTronAdapter());
  res.json({ success: true, data: balance });
}

module.exports = {
  addWallet:        asyncHandler(addWallet),
  listWallets:      asyncHandler(listWallets),
  getWallet:        asyncHandler(getWallet),
  setWalletStatus:  asyncHandler(setWalletStatus),
  getWalletBalance: asyncHandler(getWalletBalance),
};
