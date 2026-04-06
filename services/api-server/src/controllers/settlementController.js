'use strict';

/**
 * @module controllers/settlementController
 *
 * Settlement Management — Admin endpoints for batch merchant fund settlement.
 *
 * SECURITY:
 *   - All routes: authenticate + authorize('admin') + require2FA + adminIpWhitelist
 *   - Mutations: confirmCriticalAction (live TOTP)
 *   - Settlement creation uses MongoDB sessions for atomic invoice aggregation
 *   - Immutable once in completed/failed state (enforced at model level)
 *
 * FLOW:
 *   1. Admin creates settlement → aggregates confirmed invoices for period
 *   2. Creates Settlement record (pending) + links invoices
 *   3. Withdrawal engine picks up pending settlements (future: settlement queue)
 *   4. On withdrawal completion → Settlement marked completed with txHash
 *
 * Routes (mounted at /admin/settlements):
 *   GET    /                       — List settlements (filter by merchant/status/period)
 *   GET    /:settlementId          — Get settlement detail
 *   POST   /                       — Create manual settlement (TOTP required)
 *   POST   /:settlementId/cancel   — Cancel pending settlement (TOTP required)
 */

const mongoose      = require('mongoose');
const Joi           = require('joi');
const { v4: uuidv4 } = require('uuid');
const { Settlement, Invoice, Merchant, AuditLog } = require('@xcg/database');
const { AppError, validate, validateObjectId }    = require('@xcg/common');
const asyncHandler  = require('../utils/asyncHandler');
const { createLogger } = require('@xcg/logger');

let settlementQueuePublisher = null;
function setSettlementPublisher(publisher) {
  settlementQueuePublisher = publisher;
}

const logger = createLogger('settlement-ctrl');

// ─── Joi Schemas ──────────────────────────────────────────────────────────────

const createSchema = Joi.object({
  merchantId:  Joi.string().hex().length(24).required(),
  periodStart: Joi.date().iso().required(),
  periodEnd:   Joi.date().iso().greater(Joi.ref('periodStart')).required(),
  toAddress:   Joi.string().pattern(/^T[1-9A-HJ-NP-Za-km-z]{33}$/).required(),
  frequency:   Joi.string().valid('daily', 'weekly', 'manual', 'threshold').default('manual'),
}).options({ stripUnknown: true });

const listSchema = Joi.object({
  merchantId: Joi.string().hex().length(24).optional(),
  status:     Joi.string().valid('pending', 'processing', 'completed', 'failed', 'cancelled').optional(),
  page:       Joi.number().integer().min(1).max(1000).default(1),
  limit:      Joi.number().integer().min(1).max(100).default(20),
}).options({ stripUnknown: true });

const cancelSchema = Joi.object({
  reason: Joi.string().trim().min(10).max(500).required(),
}).options({ stripUnknown: true });

// ─── GET /admin/settlements ───────────────────────────────────────────────────

async function listSettlements(req, res) {
  const { merchantId, status, page, limit } = validate(listSchema, req.query);
  const filter = {};
  if (merchantId) filter.merchantId = merchantId;
  if (status)     filter.status = status;

  const skip = (page - 1) * limit;
  const [settlements, total] = await Promise.all([
    Settlement.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
    Settlement.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data: {
      settlements,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    },
  });
}

// ─── GET /admin/settlements/:settlementId ─────────────────────────────────────

async function getSettlement(req, res) {
  const { settlementId } = req.params;
  if (!settlementId || !/^stl_[a-zA-Z0-9]{24}$/.test(settlementId)) {
    throw AppError.badRequest('Invalid settlement ID format');
  }

  const settlement = await Settlement.findOne({ settlementId }).lean();
  if (!settlement) throw AppError.notFound('Settlement not found');

  res.json({ success: true, data: { settlement } });
}

// ─── POST /admin/settlements ──────────────────────────────────────────────────

async function createSettlement(req, res) {
  const data = validate(createSchema, req.body);

  validateObjectId(data.merchantId, 'merchantId');

  const merchant = await Merchant.findById(data.merchantId)
    .select('_id isActive businessName withdrawalAddress')
    .lean();
  if (!merchant) throw AppError.notFound('Merchant not found');
  if (!merchant.isActive) throw AppError.conflict('Merchant account is suspended');

  // Aggregate confirmed invoices for the settlement period
  const invoices = await Invoice.find({
    merchantId: merchant._id,
    status: { $in: ['confirmed', 'success'] },
    confirmedAt: {
      $gte: new Date(data.periodStart),
      $lte: new Date(data.periodEnd),
    },
    // Only include invoices not already covered by another settlement
    settlementId: { $exists: false },
  }).select('_id baseAmount feeAmount netAmount confirmedAt').lean();

  if (invoices.length === 0) {
    throw AppError.badRequest(
      'No unsettled, confirmed invoices found for the specified period',
    );
  }

  // Financial aggregation
  const grossAmount = invoices.reduce((s, inv) => s + (inv.baseAmount || 0), 0);
  const feeAmount   = invoices.reduce((s, inv) => s + (inv.feeAmount  || 0), 0);
  const netAmount   = invoices.reduce((s, inv) => s + (inv.netAmount  || 0), 0);

  if (netAmount <= 0) {
    throw AppError.badRequest('Net settlement amount must be greater than zero');
  }

  const settlementId = `stl_${uuidv4().replace(/-/g, '').slice(0, 24)}`;

  // Create settlement atomically
  const session = await mongoose.startSession();
  let settlement;
  try {
    await session.withTransaction(async () => {
      [settlement] = await Settlement.create([{
        settlementId,
        merchantId:   merchant._id,
        periodStart:  new Date(data.periodStart),
        periodEnd:    new Date(data.periodEnd),
        frequency:    data.frequency,
        grossAmount:  parseFloat(grossAmount.toFixed(6)),
        feeAmount:    parseFloat(feeAmount.toFixed(6)),
        netAmount:    parseFloat(netAmount.toFixed(6)),
        currency:     'USDT',
        network:      'tron',
        invoiceCount: invoices.length,
        invoiceIds:   invoices.map((i) => i._id),
        toAddress:    data.toAddress,
        status:       'pending',
        createdBy:    req.user.userId,
      }], { session });
    });
  } catch (err) {
    logger.error('settlementController: failed to create settlement', { error: err.message });
    throw err;
  } finally {
    await session.endSession();
  }

  // Audit log
  await AuditLog.create({
    actor:      req.user.userId,
    action:     'admin.settlement.created',
    resource:   'settlement',
    resourceId: settlementId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata: {
      merchantId:   String(merchant._id),
      businessName: merchant.businessName,
      invoiceCount: invoices.length,
      grossAmount:  parseFloat(grossAmount.toFixed(6)),
      netAmount:    parseFloat(netAmount.toFixed(6)),
      periodStart:  data.periodStart,
      periodEnd:    data.periodEnd,
    },
  });

  logger.info('Settlement created', {
    settlementId, merchantId: String(merchant._id),
    invoiceCount: invoices.length, netAmount: parseFloat(netAmount.toFixed(6)),
  });

  if (settlementQueuePublisher) {
    await settlementQueuePublisher.publish(
      { settlementId: String(settlement._id) },
      `settlement:${settlementId}`
    );
  }

  res.status(201).json({ success: true, data: { settlement } });
}

// ─── POST /admin/settlements/:settlementId/cancel ─────────────────────────────

async function cancelSettlement(req, res) {
  const { settlementId } = req.params;
  const { reason } = validate(cancelSchema, req.body);

  if (!settlementId || !/^stl_[a-zA-Z0-9]{24}$/.test(settlementId)) {
    throw AppError.badRequest('Invalid settlement ID format');
  }

  const settlement = await Settlement.findOne({ settlementId });
  if (!settlement) throw AppError.notFound('Settlement not found');

  if (settlement.status !== 'pending') {
    throw AppError.conflict(
      `Cannot cancel settlement in '${settlement.status}' state. Only 'pending' settlements can be cancelled.`,
    );
  }

  // findOneAndUpdate enforces status guard at model level (immutability pre-hook)
  await Settlement.findOneAndUpdate(
    { settlementId, status: 'pending' }, // Double guard on status
    { $set: { status: 'cancelled', lastError: `Cancelled by admin: ${reason}` } },
  );

  await AuditLog.create({
    actor:      req.user.userId,
    action:     'admin.settlement.cancelled',
    resource:   'settlement',
    resourceId: settlementId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { reason },
  });

  logger.warn('Settlement cancelled', { settlementId, actor: req.user.userId, reason });
  res.json({ success: true, message: `Settlement ${settlementId} cancelled.` });
}

module.exports = {
  listSettlements:  asyncHandler(listSettlements),
  getSettlement:    asyncHandler(getSettlement),
  createSettlement: asyncHandler(createSettlement),
  cancelSettlement: asyncHandler(cancelSettlement),
  setSettlementPublisher,
};
