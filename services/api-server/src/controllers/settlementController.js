'use strict';

/**
 * @module controllers/settlementController
 *
 * Settlement Management — Admin endpoints for merchant fund settlement batches.
 *
 * FLOW:
 *   1. System or admin triggers settlement for a merchant
 *   2. Aggregates confirmed invoices for the settlement period
 *   3. Creates Settlement record → creates Withdrawal → signing → broadcast
 *   4. Settlement marked completed on confirmation
 *
 * Routes (mounted at /admin/settlements):
 *   GET    /                    — List settlements (filterable by merchant, status)
 *   GET    /:settlementId       — Get settlement detail
 *   POST   /                    — Create manual settlement (TOTP)
 *   POST   /:settlementId/cancel — Cancel pending settlement (TOTP)
 */

const { v4: uuidv4 } = require('uuid');
const { Settlement, Invoice, Merchant, LedgerEntry, AuditLog, MerchantBalance } = require('@xcg/database');
const { AppError } = require('@xcg/common');
const asyncHandler = require('../utils/asyncHandler');
const logger = require('@xcg/logger').createLogger('settlement-ctrl');

// ─── GET /admin/settlements ───────────────────────────────────────────────────

async function listSettlements(req, res) {
  const { merchantId, status, page = 1, limit = 20 } = req.query;
  const filter = {};
  if (merchantId) filter.merchantId = merchantId;
  if (status) filter.status = status;

  const skip = (Math.max(1, parseInt(page, 10)) - 1) * parseInt(limit, 10);
  const [settlements, total] = await Promise.all([
    Settlement.find(filter).sort({ createdAt: -1 }).skip(skip).limit(parseInt(limit, 10)).lean(),
    Settlement.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data: { settlements, pagination: { page: parseInt(page, 10), limit: parseInt(limit, 10), total, pages: Math.ceil(total / parseInt(limit, 10)) } },
  });
}

// ─── GET /admin/settlements/:settlementId ─────────────────────────────────────

async function getSettlement(req, res) {
  const settlement = await Settlement.findOne({ settlementId: req.params.settlementId }).lean();
  if (!settlement) throw AppError.notFound('Settlement not found');
  res.json({ success: true, data: settlement });
}

// ─── POST /admin/settlements ──────────────────────────────────────────────────

async function createSettlement(req, res) {
  const { merchantId, periodStart, periodEnd, toAddress } = req.body;

  if (!merchantId || !periodStart || !periodEnd || !toAddress) {
    throw AppError.badRequest('merchantId, periodStart, periodEnd, and toAddress are required');
  }

  const merchant = await Merchant.findById(merchantId).select('_id isActive businessName').lean();
  if (!merchant || !merchant.isActive) throw AppError.notFound('Merchant not found or inactive');

  // Aggregate confirmed invoices for period
  const invoices = await Invoice.find({
    merchantId,
    status: { $in: ['confirmed', 'success'] },
    confirmedAt: { $gte: new Date(periodStart), $lte: new Date(periodEnd) },
  }).select('_id baseAmount feeAmount netAmount').lean();

  if (invoices.length === 0) {
    throw AppError.badRequest('No confirmed invoices found for the specified period');
  }

  const grossAmount = invoices.reduce((sum, inv) => sum + (inv.baseAmount || 0), 0);
  const feeAmount   = invoices.reduce((sum, inv) => sum + (inv.feeAmount || 0), 0);
  const netAmount   = invoices.reduce((sum, inv) => sum + (inv.netAmount || 0), 0);

  const settlement = await Settlement.create({
    settlementId: `stl_${uuidv4().replace(/-/g, '').slice(0, 24)}`,
    merchantId,
    periodStart: new Date(periodStart),
    periodEnd:   new Date(periodEnd),
    frequency:   'manual',
    grossAmount,
    feeAmount,
    netAmount,
    currency:    'USDT',
    network:     'tron',
    invoiceCount: invoices.length,
    invoiceIds:   invoices.map((i) => i._id),
    toAddress,
    status:      'pending',
    createdBy:   req.user._id,
  });

  await AuditLog.create({
    actor:      req.user.userId || String(req.user._id),
    action:     'admin.settlement_created',
    resource:   'settlement',
    resourceId: settlement.settlementId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { merchantId, invoiceCount: invoices.length, netAmount },
  });

  logger.info('Settlement created', { settlementId: settlement.settlementId, merchantId, netAmount });
  res.status(201).json({ success: true, data: settlement });
}

// ─── POST /admin/settlements/:settlementId/cancel ─────────────────────────────

async function cancelSettlement(req, res) {
  const { settlementId } = req.params;
  const { reason } = req.body;

  if (!reason || reason.length < 10) {
    throw AppError.badRequest('Cancellation reason required (min 10 chars)');
  }

  const settlement = await Settlement.findOne({ settlementId });
  if (!settlement) throw AppError.notFound('Settlement not found');
  if (settlement.status !== 'pending') {
    throw AppError.conflict(`Cannot cancel settlement in '${settlement.status}' state`);
  }

  await Settlement.findOneAndUpdate(
    { settlementId, status: 'pending' },
    { $set: { status: 'cancelled', lastError: `Cancelled: ${reason}` } },
  );

  await AuditLog.create({
    actor:      req.user.userId || String(req.user._id),
    action:     'admin.settlement_cancelled',
    resource:   'settlement',
    resourceId: settlementId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { reason },
  });

  logger.warn('Settlement cancelled', { settlementId, reason });
  res.json({ success: true, message: `Settlement ${settlementId} cancelled.` });
}

module.exports = {
  listSettlements:  asyncHandler(listSettlements),
  getSettlement:    asyncHandler(getSettlement),
  createSettlement: asyncHandler(createSettlement),
  cancelSettlement: asyncHandler(cancelSettlement),
};
