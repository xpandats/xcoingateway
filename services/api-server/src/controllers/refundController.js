'use strict';

/**
 * @module controllers/refundController
 *
 * Refund Management — Admin + merchant endpoints for processing refunds.
 *
 * FLOW:
 *   1. Refund created (from dispute resolution or merchant request)
 *   2. Admin approves → status: approved → queued for signing
 *   3. Signing service signs → broadcasts → confirms
 *   4. Ledger entries created
 *
 * Routes (mounted at /admin/refunds):
 *   GET    /                   — List refunds
 *   GET    /:refundId          — Get refund detail
 *   POST   /                   — Create refund request
 *   POST   /:refundId/approve  — Approve refund (TOTP)
 *   POST   /:refundId/reject   — Reject refund (TOTP)
 */

const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { Refund, Invoice, Merchant, AuditLog, MerchantBalance } = require('@xcg/database');
const { AppError } = require('@xcg/common');
const asyncHandler = require('../utils/asyncHandler');
const logger = require('@xcg/logger').createLogger('refund-ctrl');

// ─── GET /admin/refunds ───────────────────────────────────────────────────────

async function listRefunds(req, res) {
  const { merchantId, status, invoiceId, page = 1, limit = 20 } = req.query;
  const filter = {};
  if (merchantId) filter.merchantId = merchantId;
  if (status) filter.status = status;
  if (invoiceId) filter.invoiceId = invoiceId;

  const skip = (Math.max(1, parseInt(page, 10)) - 1) * parseInt(limit, 10);
  const [refunds, total] = await Promise.all([
    Refund.find(filter).sort({ createdAt: -1 }).skip(skip).limit(parseInt(limit, 10)).lean(),
    Refund.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data: { refunds, pagination: { page: parseInt(page, 10), limit: parseInt(limit, 10), total, pages: Math.ceil(total / parseInt(limit, 10)) } },
  });
}

// ─── GET /admin/refunds/:refundId ─────────────────────────────────────────────

async function getRefund(req, res) {
  const refund = await Refund.findOne({ refundId: req.params.refundId }).lean();
  if (!refund) throw AppError.notFound('Refund not found');
  res.json({ success: true, data: refund });
}

// ─── POST /admin/refunds ──────────────────────────────────────────────────────

async function createRefund(req, res) {
  const { invoiceId, refundAmount, toAddress, reason, notes } = req.body;

  if (!invoiceId || !refundAmount || !toAddress || !reason) {
    throw AppError.badRequest('invoiceId, refundAmount, toAddress, and reason are required');
  }

  const invoice = await Invoice.findById(invoiceId)
    .select('merchantId baseAmount netAmount status')
    .lean();
  if (!invoice) throw AppError.notFound('Invoice not found');

  // Check amount cap — can't refund more than the original
  if (refundAmount > (invoice.netAmount || invoice.baseAmount)) {
    throw AppError.badRequest(`Refund amount (${refundAmount}) exceeds original amount (${invoice.netAmount || invoice.baseAmount})`);
  }

  // Check for duplicate refunds on same invoice
  const existingRefund = await Refund.findOne({
    invoiceId, status: { $nin: ['failed', 'rejected'] },
  }).select('refundId status').lean();
  if (existingRefund) {
    throw AppError.conflict(`Active refund already exists for this invoice: ${existingRefund.refundId} (${existingRefund.status})`);
  }

  // Check merchant balance
  const balance = await MerchantBalance.findOne({ merchantId: invoice.merchantId }).lean();
  if (balance && balance.availableBalance < refundAmount) {
    throw AppError.badRequest(`Insufficient merchant balance (${balance.availableBalance} < ${refundAmount})`);
  }

  const refund = await Refund.create({
    refundId:       `ref_${uuidv4().replace(/-/g, '').slice(0, 24)}`,
    invoiceId,
    merchantId:     invoice.merchantId,
    originalAmount: invoice.netAmount || invoice.baseAmount,
    refundAmount,
    currency:       'USDT',
    network:        'tron',
    toAddress,
    reason,
    notes:          notes || '',
    status:         'pending',
    requestedBy:    req.user._id,
    idempotencyKey: req.headers['x-idempotency-key'] || null,
  });

  await AuditLog.create({
    actor:      req.user.userId || String(req.user._id),
    action:     'admin.refund_created',
    resource:   'refund',
    resourceId: refund.refundId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { invoiceId: String(invoiceId), refundAmount, reason },
  });

  logger.info('Refund created', { refundId: refund.refundId, invoiceId: String(invoiceId), refundAmount });
  res.status(201).json({ success: true, data: refund.toSafeJSON() });
}

// ─── POST /admin/refunds/:refundId/approve ────────────────────────────────────

async function approveRefund(req, res) {
  const { refundId } = req.params;

  const refund = await Refund.findOne({ refundId });
  if (!refund) throw AppError.notFound('Refund not found');
  if (refund.status !== 'pending') {
    throw AppError.conflict(`Cannot approve refund in '${refund.status}' state`);
  }

  refund.status     = 'approved';
  refund.approvedBy = req.user._id;
  refund.approvedAt = new Date();
  await refund.save();

  await AuditLog.create({
    actor:      req.user.userId || String(req.user._id),
    action:     'admin.refund_approved',
    resource:   'refund',
    resourceId: refundId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
  });

  logger.info('Refund approved', { refundId });
  res.json({ success: true, data: refund.toSafeJSON() });
}

// ─── POST /admin/refunds/:refundId/reject ─────────────────────────────────────

async function rejectRefund(req, res) {
  const { refundId } = req.params;
  const { reason } = req.body;

  if (!reason || reason.length < 5) {
    throw AppError.badRequest('Rejection reason required (min 5 chars)');
  }

  const refund = await Refund.findOne({ refundId });
  if (!refund) throw AppError.notFound('Refund not found');
  if (refund.status !== 'pending') {
    throw AppError.conflict(`Cannot reject refund in '${refund.status}' state`);
  }

  refund.status          = 'rejected';
  refund.rejectedBy      = req.user._id;
  refund.rejectedAt      = new Date();
  refund.rejectionReason = reason;
  await refund.save();

  await AuditLog.create({
    actor:      req.user.userId || String(req.user._id),
    action:     'admin.refund_rejected',
    resource:   'refund',
    resourceId: refundId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { reason },
  });

  logger.warn('Refund rejected', { refundId, reason });
  res.json({ success: true, message: `Refund ${refundId} rejected.` });
}

module.exports = {
  listRefunds:   asyncHandler(listRefunds),
  getRefund:     asyncHandler(getRefund),
  createRefund:  asyncHandler(createRefund),
  approveRefund: asyncHandler(approveRefund),
  rejectRefund:  asyncHandler(rejectRefund),
};
