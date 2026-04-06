'use strict';

/**
 * @module controllers/refundController
 *
 * Refund Management — Admin endpoints for processing merchant refunds.
 *
 * SECURITY:
 *   - All routes: authenticate + authorize('admin') + require2FA + adminIpWhitelist
 *   - Create/Approve/Reject: confirmCriticalAction (live TOTP)
 *   - Refund amount validated against original invoice (model pre-hook + controller)
 *   - Idempotency key prevents duplicate refund creation
 *   - Balance check against MerchantBalance before creating refund
 *   - Immutable after completion (model-level pre-hooks)
 *
 * FLOW:
 *   1. createRefund  → status: 'pending'
 *   2. approveRefund → status: 'approved' (queued for signing in Phase 4 withdrawal pipeline)
 *   3. Withdrawal engine processes refund → 'signing' → 'broadcast' → 'confirmed' → 'completed'
 *   4. rejectRefund  → status: 'rejected' (admin decision with reason)
 *
 * Routes (mounted at /admin/refunds):
 *   GET    /                       — List refunds
 *   GET    /:refundId              — Get refund detail
 *   POST   /                       — Create refund (TOTP required)
 *   POST   /:refundId/approve      — Approve pending refund (TOTP required)
 *   POST   /:refundId/reject       — Reject pending refund (TOTP required)
 */

const Joi           = require('joi');
const crypto        = require('crypto');
const { Refund, Invoice, AuditLog, MerchantBalance } = require('@xcg/database');
const { AppError, validate, validateObjectId }        = require('@xcg/common');
const asyncHandler  = require('../utils/asyncHandler');
const { createLogger } = require('@xcg/logger');

const logger = createLogger('refund-ctrl');

// ─── Joi Schemas ──────────────────────────────────────────────────────────────

const createSchema = Joi.object({
  invoiceId:    Joi.string().hex().length(24).required(),
  refundAmount: Joi.number().positive().precision(6).required(),
  toAddress:    Joi.string().pattern(/^T[1-9A-HJ-NP-Za-km-z]{33}$/).required(),
  reason:       Joi.string().valid(
    'dispute_resolved', 'merchant_request', 'overpayment',
    'duplicate', 'service_issue', 'admin_decision',
  ).required(),
  notes:        Joi.string().trim().max(1000).optional().allow(''),
}).options({ stripUnknown: true });

const listSchema = Joi.object({
  merchantId: Joi.string().hex().length(24).optional(),
  status:     Joi.string().valid(
    'pending', 'approved', 'queued', 'signing', 'broadcast',
    'confirming', 'completed', 'failed', 'rejected',
  ).optional(),
  invoiceId:  Joi.string().hex().length(24).optional(),
  page:       Joi.number().integer().min(1).max(1000).default(1),
  limit:      Joi.number().integer().min(1).max(100).default(20),
}).options({ stripUnknown: true });

const rejectSchema = Joi.object({
  reason: Joi.string().trim().min(5).max(500).required(),
}).options({ stripUnknown: true });

// ─── GET /admin/refunds ───────────────────────────────────────────────────────

async function listRefunds(req, res) {
  const { merchantId, status, invoiceId, page, limit } = validate(listSchema, req.query);
  const filter = {};
  if (merchantId) filter.merchantId = merchantId;
  if (status)     filter.status = status;
  if (invoiceId)  filter.invoiceId = invoiceId;

  const skip = (page - 1) * limit;
  const [refunds, total] = await Promise.all([
    Refund.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
    Refund.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data: { refunds, pagination: { page, limit, total, pages: Math.ceil(total / limit) } },
  });
}

// ─── GET /admin/refunds/:refundId ─────────────────────────────────────────────

async function getRefund(req, res) {
  const { refundId } = req.params;
  if (!refundId || !/^ref_[a-zA-Z0-9]{24}$/.test(refundId)) {
    throw AppError.badRequest('Invalid refund ID format');
  }

  const refund = await Refund.findOne({ refundId }).lean();
  if (!refund) throw AppError.notFound('Refund not found');
  res.json({ success: true, data: { refund } });
}

// ─── POST /admin/refunds ──────────────────────────────────────────────────────

async function createRefund(req, res) {
  const data = validate(createSchema, req.body);

  validateObjectId(data.invoiceId, 'invoiceId');

  // Load invoice — must exist and be confirmed
  const invoice = await Invoice.findById(data.invoiceId)
    .select('_id merchantId baseAmount feeAmount netAmount status confirmedAt txHash')
    .lean();
  if (!invoice) throw AppError.notFound('Invoice not found');

  if (!['confirmed', 'success'].includes(invoice.status)) {
    throw AppError.conflict(
      `Refunds can only be issued for confirmed payments. Invoice status: '${invoice.status}'`,
    );
  }

  // Amount cap — cannot refund more than original net amount
  const originalAmount = invoice.netAmount || invoice.baseAmount;
  if (data.refundAmount > originalAmount) {
    throw AppError.badRequest(
      `Refund amount (${data.refundAmount}) exceeds original invoice amount (${originalAmount})`,
    );
  }

  // Idempotency — prevent duplicate refunds on same invoice
  const idempotencyKey = req.headers['x-idempotency-key'] || null;
  if (idempotencyKey) {
    const dupe = await Refund.findOne({ idempotencyKey }).select('refundId status').lean();
    if (dupe) {
      // Idempotent response — return existing record
      logger.info('refundController: idempotent refund request', { refundId: dupe.refundId });
      return res.status(200).json({ success: true, data: { refund: dupe }, idempotent: true });
    }
  }

  // Check no active refund already exists for this invoice
  const existingRefund = await Refund.findOne({
    invoiceId: invoice._id,
    status:    { $nin: ['failed', 'rejected'] },
  }).select('refundId status').lean();

  if (existingRefund) {
    throw AppError.conflict(
      `An active refund already exists for invoice ${data.invoiceId}: ` +
      `${existingRefund.refundId} (status: ${existingRefund.status})`,
    );
  }

  // Check merchant balance — guard against refunding more than available
  const balance = await MerchantBalance.findOne({ merchantId: invoice.merchantId })
    .select('availableBalance')
    .lean();

  if (balance && balance.availableBalance < data.refundAmount) {
    throw AppError.conflict(
      `Insufficient merchant balance. Available: ${balance.availableBalance}, Requested: ${data.refundAmount}`,
    );
  }

  const refundId = `ref_${crypto.randomBytes(12).toString('hex')}`;

  const refund = await Refund.create({
    refundId,
    invoiceId:      invoice._id,
    merchantId:     invoice.merchantId,
    originalAmount: parseFloat(originalAmount.toFixed(6)),
    refundAmount:   parseFloat(data.refundAmount.toFixed(6)),
    currency:       'USDT',
    network:        'tron',
    toAddress:      data.toAddress,
    reason:         data.reason,
    notes:          data.notes || '',
    status:         'pending',
    requestedBy:    req.user.userId, // String userId from JWT
    idempotencyKey: idempotencyKey || undefined,
  });

  await AuditLog.create({
    actor:      req.user.userId,
    action:     'admin.refund.created',
    resource:   'refund',
    resourceId: refundId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata: {
      invoiceId:     String(invoice._id),
      refundAmount:  data.refundAmount,
      originalAmount,
      reason:        data.reason,
    },
  });

  logger.info('Refund created', { refundId, invoiceId: String(invoice._id), refundAmount: data.refundAmount });
  res.status(201).json({ success: true, data: { refund: refund.toSafeJSON() } });
}

// ─── POST /admin/refunds/:refundId/approve ────────────────────────────────────

async function approveRefund(req, res) {
  const { refundId } = req.params;
  if (!refundId || !/^ref_[a-zA-Z0-9]{24}$/.test(refundId)) {
    throw AppError.badRequest('Invalid refund ID format');
  }

  // Load full document for .save() — not lean()
  const refund = await Refund.findOne({ refundId });
  if (!refund) throw AppError.notFound('Refund not found');

  if (refund.status !== 'pending') {
    throw AppError.conflict(
      `Cannot approve refund in '${refund.status}' state. Only 'pending' refunds can be approved.`,
    );
  }

  refund.status     = 'approved';
  refund.approvedBy = req.user.userId;
  refund.approvedAt = new Date();
  await refund.save();

  await AuditLog.create({
    actor:      req.user.userId,
    action:     'admin.refund.approved',
    resource:   'refund',
    resourceId: refundId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata: {
      refundAmount: refund.refundAmount,
      invoiceId:    String(refund.invoiceId),
    },
  });

  logger.info('Refund approved', { refundId, actor: req.user.userId });
  res.json({ success: true, data: { refund: refund.toSafeJSON() } });
}

// ─── POST /admin/refunds/:refundId/reject ─────────────────────────────────────

async function rejectRefund(req, res) {
  const { refundId } = req.params;
  const { reason } = validate(rejectSchema, req.body);

  if (!refundId || !/^ref_[a-zA-Z0-9]{24}$/.test(refundId)) {
    throw AppError.badRequest('Invalid refund ID format');
  }

  const refund = await Refund.findOne({ refundId });
  if (!refund) throw AppError.notFound('Refund not found');

  if (refund.status !== 'pending') {
    throw AppError.conflict(
      `Cannot reject refund in '${refund.status}' state. Only 'pending' refunds can be rejected.`,
    );
  }

  refund.status          = 'rejected';
  refund.rejectedBy      = req.user.userId;
  refund.rejectedAt      = new Date();
  refund.rejectionReason = reason;
  await refund.save();

  await AuditLog.create({
    actor:      req.user.userId,
    action:     'admin.refund.rejected',
    resource:   'refund',
    resourceId: refundId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata: {
      reason,
      refundAmount: refund.refundAmount,
      invoiceId:    String(refund.invoiceId),
    },
  });

  logger.warn('Refund rejected', { refundId, actor: req.user.userId, reason });
  res.json({ success: true, message: `Refund ${refundId} rejected.` });
}

module.exports = {
  listRefunds:   asyncHandler(listRefunds),
  getRefund:     asyncHandler(getRefund),
  createRefund:  asyncHandler(createRefund),
  approveRefund: asyncHandler(approveRefund),
  rejectRefund:  asyncHandler(rejectRefund),
};
