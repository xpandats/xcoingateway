'use strict';

/**
 * @module controllers/walletTransferController
 *
 * Internal Wallet Transfer Management — Hot-to-cold sweeps, gas top-ups, consolidation.
 *
 * SECURITY:
 *   - List/Get: authenticate + authorize('admin') + require2FA + adminIpWhitelist
 *   - Create:   above + super_admin role + confirmCriticalAction (live TOTP)
 *   - Self-transfer guard: fromWalletId !== toWalletId
 *   - Both wallets must exist and be active
 *   - Amount validated as positive number
 *   - All creates logged to AuditLog with wallet addresses (not keys — never logged)
 *
 * WalletTransfer is created here → signing-service picks it up from queue (Phase 3 wiring)
 *
 * Routes (mounted at /admin/transfers):
 *   GET    /                   — List transfers
 *   GET    /:transferId        — Get transfer detail
 *   POST   /                   — Create manual transfer (super_admin + TOTP)
 */

const Joi           = require('joi');
const crypto        = require('crypto');
const { WalletTransfer, Wallet, AuditLog } = require('@xcg/database');
const { AppError, validate, validateObjectId } = require('@xcg/common');
const asyncHandler  = require('../utils/asyncHandler');
const { createLogger } = require('@xcg/logger');

const logger = createLogger('transfer-ctrl');

// ─── Joi Schemas ──────────────────────────────────────────────────────────────

const createSchema = Joi.object({
  fromWalletId: Joi.string().hex().length(24).required(),
  toWalletId:   Joi.string().hex().length(24).required()
    .invalid(Joi.ref('fromWalletId')),  // Cannot self-transfer at schema level
  amount:       Joi.number().positive().precision(6).required(),
  transferType: Joi.string().valid(
    'hot_to_cold', 'cold_to_hot', 'gas_topup', 'wallet_retire', 'consolidation',
  ).required(),
  token:        Joi.string().valid('USDT', 'TRX').default('USDT'),
  reason:       Joi.string().trim().max(500).optional().allow(''),
}).options({ stripUnknown: true });

const listSchema = Joi.object({
  fromWalletId: Joi.string().hex().length(24).optional(),
  toWalletId:   Joi.string().hex().length(24).optional(),
  transferType: Joi.string().valid(
    'hot_to_cold', 'cold_to_hot', 'gas_topup', 'wallet_retire', 'consolidation',
  ).optional(),
  status:       Joi.string().valid(
    'pending', 'signing', 'broadcast', 'confirming', 'completed', 'failed', 'cancelled',
  ).optional(),
  page:         Joi.number().integer().min(1).max(1000).default(1),
  limit:        Joi.number().integer().min(1).max(100).default(20),
}).options({ stripUnknown: true });

// ─── GET /admin/transfers ─────────────────────────────────────────────────────

async function listTransfers(req, res) {
  const { fromWalletId, toWalletId, transferType, status, page, limit } = validate(listSchema, req.query);
  const filter = {};
  if (fromWalletId) filter.fromWalletId = fromWalletId;
  if (toWalletId)   filter.toWalletId   = toWalletId;
  if (transferType) filter.transferType  = transferType;
  if (status)       filter.status        = status;

  const skip = (page - 1) * limit;
  const [transfers, total] = await Promise.all([
    WalletTransfer.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
    WalletTransfer.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data: { transfers, pagination: { page, limit, total, pages: Math.ceil(total / limit) } },
  });
}

// ─── GET /admin/transfers/:transferId ─────────────────────────────────────────

async function getTransfer(req, res) {
  const { transferId } = req.params;
  if (!transferId || !/^trf_[a-zA-Z0-9]{24}$/.test(transferId)) {
    throw AppError.badRequest('Invalid transfer ID format');
  }

  const transfer = await WalletTransfer.findOne({ transferId }).lean();
  if (!transfer) throw AppError.notFound('Wallet transfer not found');
  res.json({ success: true, data: { transfer } });
}

// ─── POST /admin/transfers ────────────────────────────────────────────────────

async function createTransfer(req, res) {
  const data = validate(createSchema, req.body);

  validateObjectId(data.fromWalletId, 'fromWalletId');
  validateObjectId(data.toWalletId, 'toWalletId');

  // Extra self-transfer guard (in case Joi ref validation is bypassed somehow)
  if (data.fromWalletId === data.toWalletId) {
    throw AppError.badRequest('Source and destination wallet cannot be the same');
  }

  // Load both wallets in parallel
  const [fromWallet, toWallet] = await Promise.all([
    Wallet.findById(data.fromWalletId).select('_id address isActive walletType').lean(),
    Wallet.findById(data.toWalletId).select('_id address isActive walletType').lean(),
  ]);

  if (!fromWallet) throw AppError.notFound('Source wallet not found');
  if (!toWallet)   throw AppError.notFound('Destination wallet not found');

  if (!fromWallet.isActive) throw AppError.conflict('Source wallet is inactive');
  if (!toWallet.isActive)   throw AppError.conflict('Destination wallet is inactive');

  const transferId = `trf_${crypto.randomBytes(12).toString('hex')}`;

  const transfer = await WalletTransfer.create({
    transferId,
    fromWalletId: fromWallet._id,
    fromAddress:  fromWallet.address,
    toWalletId:   toWallet._id,
    toAddress:    toWallet.address,
    transferType: data.transferType,
    amount:       parseFloat(data.amount.toFixed(6)),
    token:        data.token,
    network:      'tron',
    status:       'pending',
    triggeredBy:  `admin:${req.user.userId}`,
    reason:       data.reason || '',
  });

  await AuditLog.create({
    actor:      req.user.userId,
    action:     'admin.wallet_transfer.created',
    resource:   'wallet_transfer',
    resourceId: transferId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata: {
      fromAddress:  fromWallet.address,   // Log address, never private key
      toAddress:    toWallet.address,
      amount:       data.amount,
      transferType: data.transferType,
      token:        data.token,
    },
  });

  logger.info('Wallet transfer created', {
    transferId, transferType: data.transferType,
    from: fromWallet.address.slice(0, 8),
    to:   toWallet.address.slice(0, 8),
    amount: data.amount, token: data.token,
  });

  res.status(201).json({ success: true, data: { transfer } });
}

module.exports = {
  listTransfers:  asyncHandler(listTransfers),
  getTransfer:    asyncHandler(getTransfer),
  createTransfer: asyncHandler(createTransfer),
};
