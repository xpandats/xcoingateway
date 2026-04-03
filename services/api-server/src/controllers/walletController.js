'use strict';

/**
 * @module controllers/walletController
 *
 * Wallet Controller — Admin-only REST endpoints.
 *
 * ALL routes here require:
 *   1. authenticate middleware (valid JWT)
 *   2. authorize('admin') middleware (admin role only)
 *   3. Admin IP whitelist (enforced in router)
 *
 * Routes:
 *   POST   /admin/wallets            — Add new wallet
 *   GET    /admin/wallets            — List wallets
 *   GET    /admin/wallets/:id        — Get single wallet
 *   PUT    /admin/wallets/:id/status — Activate/deactivate
 *   GET    /admin/wallets/:id/balance— On-chain balance check
 */

const { schemas, validate } = require('@xcg/common');
const { AppError }           = require('@xcg/common');
const { config }             = require('../config');
const WalletService          = require('../services/walletService');
const { encrypt }            = require('@xcg/crypto');
const { TronAdapter }        = require('@xcg/tron');

// Shared lazy-init singletons
let _walletService = null;
let _tronAdapter   = null;

function getWalletService() {
  if (!_walletService) {
    _walletService = new WalletService({ masterKey: config.encryption.masterKey, logger: require('@xcg/logger').createLogger('wallet-svc') });
  }
  return _walletService;
}

function getTronAdapter() {
  if (!_tronAdapter) {
    _tronAdapter = new TronAdapter({ network: config.tron.network, apiKey: config.tron.apiKey }, require('@xcg/logger').createLogger('tron-adapter'));
  }
  return _tronAdapter;
}

// ─── POST /admin/wallets ─────────────────────────────────────────────────────

const addWalletSchema = require('joi').object({
  address:    require('joi').string().pattern(/^T[1-9A-HJ-NP-Za-km-z]{33}$/).required(),
  privateKey: require('joi').string().hex().length(64).required(), // 32 bytes hex
  label:      require('joi').string().trim().max(50).optional().allow(''),
  network:    require('joi').string().valid('tron').default('tron'),
}).options({ stripUnknown: true });

async function addWallet(req, res) {
  const data = validate(addWalletSchema, req.body);

  const wallet = await getWalletService().addWallet(data, {
    userId: req.user._id,
    ip: req.ip,
  });

  // SECURITY: privateKey must NOT appear in any response
  // The walletService.addWallet() encrypts it and returns toSafeJSON()
  res.status(201).json({ success: true, data: { wallet } });
}

// ─── GET /admin/wallets ──────────────────────────────────────────────────────

async function listWallets(req, res) {
  const wallets = await getWalletService().listWallets(req.query);
  res.json({ success: true, data: { wallets, count: wallets.length } });
}

// ─── GET /admin/wallets/:id ──────────────────────────────────────────────────

async function getWallet(req, res) {
  const wallet = await require('@xcg/database').Wallet
    .findById(req.params.id)
    .select('-encryptedPrivateKey -derivationSalt')
    .lean();
  if (!wallet) throw AppError.notFound('Wallet not found');
  res.json({ success: true, data: { wallet } });
}

// ─── PUT /admin/wallets/:id/status ──────────────────────────────────────────

async function setWalletStatus(req, res) {
  const { isActive } = req.body;
  if (typeof isActive !== 'boolean') throw AppError.badRequest('isActive must be boolean');

  const wallet = await getWalletService().setWalletStatus(
    req.params.id, isActive, { userId: req.user._id, ip: req.ip },
  );
  res.json({ success: true, data: { wallet } });
}

// ─── GET /admin/wallets/:id/balance ─────────────────────────────────────────

async function getWalletBalance(req, res) {
  const balance = await getWalletService().getWalletBalance(req.params.id, getTronAdapter());
  res.json({ success: true, data: balance });
}

module.exports = { addWallet, listWallets, getWallet, setWalletStatus, getWalletBalance };
