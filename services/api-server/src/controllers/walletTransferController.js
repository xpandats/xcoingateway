'use strict';

/**
 * @module controllers/walletTransferController
 *
 * Internal Wallet Transfer Management — Hot-to-cold sweeps, gas top-ups, consolidation.
 *
 * Routes (mounted at /admin/transfers):
 *   GET    /                   — List transfers
 *   GET    /:transferId        — Get transfer detail
 *   POST   /                   — Create manual transfer (TOTP)
 */

const { v4: uuidv4 } = require('uuid');
const { WalletTransfer, Wallet, AuditLog } = require('@xcg/database');
const { AppError } = require('@xcg/common');
const asyncHandler = require('../utils/asyncHandler');
const logger = require('@xcg/logger').createLogger('transfer-ctrl');

// ─── GET /admin/transfers ─────────────────────────────────────────────────────

async function listTransfers(req, res) {
  const { fromWalletId, toWalletId, transferType, status, page = 1, limit = 20 } = req.query;
  const filter = {};
  if (fromWalletId)  filter.fromWalletId = fromWalletId;
  if (toWalletId)    filter.toWalletId = toWalletId;
  if (transferType)  filter.transferType = transferType;
  if (status)        filter.status = status;

  const skip = (Math.max(1, parseInt(page, 10)) - 1) * parseInt(limit, 10);
  const [transfers, total] = await Promise.all([
    WalletTransfer.find(filter).sort({ createdAt: -1 }).skip(skip).limit(parseInt(limit, 10)).lean(),
    WalletTransfer.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data: { transfers, pagination: { page: parseInt(page, 10), limit: parseInt(limit, 10), total, pages: Math.ceil(total / parseInt(limit, 10)) } },
  });
}

// ─── GET /admin/transfers/:transferId ─────────────────────────────────────────

async function getTransfer(req, res) {
  const transfer = await WalletTransfer.findOne({ transferId: req.params.transferId }).lean();
  if (!transfer) throw AppError.notFound('Transfer not found');
  res.json({ success: true, data: transfer });
}

// ─── POST /admin/transfers ────────────────────────────────────────────────────

async function createTransfer(req, res) {
  const { fromWalletId, toWalletId, amount, transferType, token, reason } = req.body;

  if (!fromWalletId || !toWalletId || !amount || !transferType) {
    throw AppError.badRequest('fromWalletId, toWalletId, amount, and transferType are required');
  }

  if (fromWalletId === toWalletId) {
    throw AppError.badRequest('Source and destination wallet cannot be the same');
  }

  const validTypes = ['hot_to_cold', 'cold_to_hot', 'gas_topup', 'wallet_retire', 'consolidation'];
  if (!validTypes.includes(transferType)) {
    throw AppError.badRequest(`Invalid transferType. Must be: ${validTypes.join(', ')}`);
  }

  const [fromWallet, toWallet] = await Promise.all([
    Wallet.findById(fromWalletId).select('_id address isActive walletType').lean(),
    Wallet.findById(toWalletId).select('_id address isActive walletType').lean(),
  ]);

  if (!fromWallet) throw AppError.notFound('Source wallet not found');
  if (!toWallet)   throw AppError.notFound('Destination wallet not found');

  const transfer = await WalletTransfer.create({
    transferId:   `trf_${uuidv4().replace(/-/g, '').slice(0, 24)}`,
    fromWalletId,
    fromAddress:  fromWallet.address,
    toWalletId,
    toAddress:    toWallet.address,
    transferType,
    amount,
    token:        token || 'USDT',
    network:      'tron',
    status:       'pending',
    triggeredBy:  `admin:${req.user._id}`,
    reason:       reason || '',
  });

  await AuditLog.create({
    actor:      req.user.userId || String(req.user._id),
    action:     'admin.wallet_transfer_created',
    resource:   'wallet_transfer',
    resourceId: transfer.transferId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   {
      fromAddress: fromWallet.address,
      toAddress:   toWallet.address,
      amount, transferType, token: token || 'USDT',
    },
  });

  logger.info('Wallet transfer created', {
    transferId: transfer.transferId, transferType,
    from: fromWallet.address.slice(0, 6), to: toWallet.address.slice(0, 6), amount,
  });

  res.status(201).json({ success: true, data: transfer });
}

module.exports = {
  listTransfers:  asyncHandler(listTransfers),
  getTransfer:    asyncHandler(getTransfer),
  createTransfer: asyncHandler(createTransfer),
};
