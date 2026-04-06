'use strict';

/**
 * @module controllers/merchantController
 *
 * Merchant Controller — Admin endpoints for merchant management.
 *
 * Routes (all require: authenticate + authorize('admin') + adminIpCheck):
 *   POST   /admin/merchants                          — Create merchant
 *   GET    /admin/merchants                          — List merchants
 *   GET    /admin/merchants/:id                      — Get merchant details
 *   PUT    /admin/merchants/:id                      — Update merchant
 *   PUT    /admin/merchants/:id/status               — Activate/suspend
 *   POST   /admin/merchants/:id/api-keys             — Generate new API key
 *   DELETE /admin/merchants/:id/api-keys/:keyId      — Revoke API key
 *   POST   /admin/merchants/:id/webhook-secret-rotate — Rotate webhook secret
 */

const Joi = require('joi');
const { validate, schemas, AppError } = require('@xcg/common');
const { config }   = require('../config');
const asyncHandler = require('../utils/asyncHandler');
const MerchantService = require('../services/merchantService');
const cache        = require('../utils/cache');
const logger = require('@xcg/logger').createLogger('merchant-ctrl');

// MerchantService is instantiated with redis in app.js once Redis is connected.
// Controllers receive redis via req.app.locals.redis (set in server.js startup).
// We create a lazy accessor so the redis client is always current.
function getSvc(req) {
  return new MerchantService({ redis: req.app.locals.redis || null });
}


// ─── Validation schemas ──────────────────────────────────────────────────────

const createSchema = Joi.object({
  userId:            Joi.string().hex().length(24).required(),
  businessName:      Joi.string().trim().min(1).max(200).required(),
  email:             Joi.string().email().optional().allow(''),
  webhookUrl:        Joi.string().uri({ scheme: ['https'] }).max(500).optional().allow(''),
  withdrawalAddress: Joi.string().pattern(/^T[1-9A-HJ-NP-Za-km-z]{33}$/).optional().allow(''),
}).options({ stripUnknown: true });

const updateSchema = Joi.object({
  businessName:               Joi.string().trim().min(1).max(200).optional(),
  webhookUrl:                 Joi.string().uri({ scheme: ['https'] }).max(500).optional().allow(''),
  withdrawalAddress:          Joi.string().pattern(/^T[1-9A-HJ-NP-Za-km-z]{33}$/).optional().allow(''),
  withdrawalAddressVerified:  Joi.boolean().optional(),
}).options({ stripUnknown: true });

const apiKeySchema = Joi.object({
  label: Joi.string().trim().max(50).optional().allow(''),
}).options({ stripUnknown: true });

const paginationSchema = Joi.object({
  page:   Joi.number().integer().min(1).max(1000).default(1),
  limit:  Joi.number().integer().min(1).max(100).default(20),
  search: Joi.string().trim().max(100).optional().allow(''),
}).options({ stripUnknown: true });

// ─── Handlers ────────────────────────────────────────────────────────────────

async function createMerchant(req, res) {
  const data = validate(createSchema, req.body);
  const result = await getSvc(req).createMerchant(data, data.userId, {
    userId: req.user._id,
    ip:     req.ip,
  });
  res.status(201).json({ success: true, data: result });
}

async function listMerchants(req, res) {
  const query  = validate(paginationSchema, req.query);
  const result = await getSvc(req).listMerchants(query);
  res.json({ success: true, data: result });
}

async function getMerchant(req, res) {
  const merchant = await getSvc(req).getMerchant(req.params.id);
  res.json({ success: true, data: { merchant } });
}

async function updateMerchant(req, res) {
  const data = validate(updateSchema, req.body);
  const merchant = await getSvc(req).updateMerchant(req.params.id, data, {
    userId: req.user._id,
    ip:     req.ip,
  });
  res.json({ success: true, data: { merchant } });
}

async function setMerchantStatus(req, res) {
  const { isActive } = req.body;
  if (typeof isActive !== 'boolean') throw AppError.badRequest('isActive must be boolean');
  const merchant = await getSvc(req).setMerchantStatus(req.params.id, isActive, {
    userId: req.user._id,
    ip:     req.ip,
  });
  res.json({ success: true, data: { merchant } });
}

async function createApiKey(req, res) {
  const { label } = validate(apiKeySchema, req.body);
  const result = await getSvc(req).createApiKey(req.params.id, label, {
    userId: req.user._id,
    ip:     req.ip,
  });
  res.status(201).json({ success: true, data: result });
}

async function revokeApiKey(req, res) {
  await getSvc(req).revokeApiKey(req.params.id, req.params.keyId, {
    userId: req.user._id,
    ip:     req.ip,
  });
  res.json({ success: true, message: 'API key revoked' });
}

async function rotateWebhookSecret(req, res) {
  const result = await getSvc(req).rotateWebhookSecret(req.params.id, {
    userId: req.user._id,
    ip:     req.ip,
  });
  res.json({ success: true, data: result });
}

// ─── Additional Admin Controls ────────────────────────────────────────────────

const mongoose = require('mongoose');
const { Invoice, Transaction, LedgerEntry, Withdrawal } = require('@xcg/database');
const { Merchant: MerchantModel } = require('@xcg/database');

// Normalise actor ID — authenticate sets req.user.userId (string), not _id
const actor = (req) => req.user.userId || String(req.user._id);

// Helper: fetch saveable Merchant document (not lean)
async function fetchMerchant(id) {
  if (!mongoose.Types.ObjectId.isValid(id)) throw AppError.badRequest('Invalid merchant ID format');
  const merchant = await MerchantModel.findById(id);
  if (!merchant) throw AppError.notFound('Merchant not found');
  return merchant;
}

const approvalSchema = Joi.object({
  action:        Joi.string().valid('approve', 'reject').required(),
  rejectedReason:Joi.string().max(500).when('action', { is: 'reject', then: Joi.required() }).optional(),
}).options({ stripUnknown: true });

const feeSchema = Joi.object({
  feePercentage: Joi.number().min(0).max(100).optional(),
  fixedFee:      Joi.number().min(0).optional(),
}).options({ stripUnknown: true });

const limitsSchema = Joi.object({
  rateLimits: Joi.object({
    invoicesPerMinute:    Joi.number().integer().min(1).max(1000).optional(),
    withdrawalsPerMinute: Joi.number().integer().min(1).max(100).optional(),
    readsPerMinute:       Joi.number().integer().min(1).max(5000).optional(),
  }).optional(),
}).options({ stripUnknown: true });

async function approveMerchant(req, res) {
  const data     = validate(approvalSchema, req.body);
  // C2 FIX: Use direct Mongoose document (not merchantService lean+hydrate)
  const merchant = await fetchMerchant(req.params.id);

  const isApprove = data.action === 'approve';
  merchant.isApproved     = isApprove;
  merchant.approvalStatus = isApprove ? 'approved' : 'rejected';
  if (isApprove) {
    merchant.approvedBy = actor(req);
    merchant.approvedAt = new Date();
  } else {
    merchant.rejectedReason = data.rejectedReason || '';
  }
  await merchant.save();

  const { AuditLog } = require('@xcg/database');
  await AuditLog.create({
    actor:      actor(req),
    action:     isApprove ? 'merchant.approved' : 'merchant.rejected',
    resource:   'merchant',
    resourceId: String(merchant._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { action: data.action, reason: data.rejectedReason },
  });

  res.json({ success: true, data: { merchant: { _id: merchant._id, approvalStatus: merchant.approvalStatus, isApproved: merchant.isApproved } } });
}

async function suspendMerchant(req, res) {
  const { reason } = req.body;
  if (!reason || !reason.trim()) throw AppError.badRequest('Suspension reason is required');

  // C2 FIX: Direct document so .save() works
  const merchant        = await fetchMerchant(req.params.id);
  merchant.isActive       = false;
  merchant.approvalStatus = 'suspended';
  await merchant.save();

  // Cache invalidation: suspendMerchant bypasses MerchantService so we must
  // invalidate here manually. A suspended merchant's API keys must stop working immediately.
  const redis  = req.app.locals.redis || null;
  const keyIds = (merchant.apiKeys || []).map((k) => k.keyId);
  await cache.invalidateMerchant(redis, String(merchant._id), keyIds);

  const { AuditLog } = require('@xcg/database');
  await AuditLog.create({
    actor:      actor(req),
    action:     'merchant.suspended',
    resource:   'merchant',
    resourceId: String(merchant._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { reason: reason.trim() },
  });

  res.json({ success: true, message: 'Merchant suspended. All payments and withdrawals for this merchant are now blocked.' });
}


async function getMerchantTransactions(req, res) {
  const { page = 1, limit = 20 } = req.query;
  const merchant = await svc.getMerchant(req.params.id);

  const [transactions, total] = await Promise.all([
    Transaction.find({ merchantId: merchant._id })
      .sort({ createdAt: -1 })
      .skip((Number(page) - 1) * Number(limit))
      .limit(Number(limit))
      .lean(),
    Transaction.countDocuments({ merchantId: merchant._id }),
  ]);

  res.json({ success: true, data: { transactions, pagination: { page: Number(page), limit: Number(limit), total } } });
}

async function getMerchantLedger(req, res) {
  const { page = 1, limit = 20 } = req.query;
  const merchant = await svc.getMerchant(req.params.id);

  const [entries, total] = await Promise.all([
    LedgerEntry.find({ merchantId: merchant._id })
      .sort({ createdAt: -1 })
      .skip((Number(page) - 1) * Number(limit))
      .limit(Number(limit))
      .lean(),
    LedgerEntry.countDocuments({ merchantId: merchant._id }),
  ]);

  res.json({ success: true, data: { entries, pagination: { page: Number(page), limit: Number(limit), total } } });
}

async function getMerchantInvoices(req, res) {
  const { page = 1, limit = 20, status } = req.query;
  const merchant = await svc.getMerchant(req.params.id);

  const filter = { merchantId: merchant._id };
  if (status) filter.status = status;

  const [invoices, total] = await Promise.all([
    Invoice.find(filter)
      .select('-amountOffset -__v')
      .sort({ createdAt: -1 })
      .skip((Number(page) - 1) * Number(limit))
      .limit(Number(limit))
      .lean(),
    Invoice.countDocuments(filter),
  ]);

  res.json({ success: true, data: { invoices, pagination: { page: Number(page), limit: Number(limit), total } } });
}

async function getMerchantStats(req, res) {
  const merchant = await svc.getMerchant(req.params.id);
  const now      = new Date();
  const last30d  = new Date(now - 30 * 86_400_000);

  const [volume, successCount, totalInvoices, balance, fees30d] = await Promise.all([
    Transaction.aggregate([
      { $match: { merchantId: merchant._id, status: 'confirmed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } },
    ]).then((r) => r[0]?.total || 0),
    Invoice.countDocuments({ merchantId: merchant._id, status: { $in: ['confirmed', 'success'] } }),
    Invoice.countDocuments({ merchantId: merchant._id }),
    LedgerEntry.aggregate([
      { $match: { merchantId: merchant._id, account: 'merchant_receivable' } },
      { $group: { _id: null, credits: { $sum: { $cond: [{ $eq: ['$type', 'credit'] }, '$amount', 0] } }, debits: { $sum: { $cond: [{ $eq: ['$type', 'debit'] }, '$amount', 0] } } } },
    ]).then((r) => r[0] ? r[0].credits - r[0].debits : 0),
    LedgerEntry.aggregate([
      { $match: { merchantId: merchant._id, account: 'platform_fee', type: 'credit', createdAt: { $gte: last30d } } },
      { $group: { _id: null, total: { $sum: '$amount' } } },
    ]).then((r) => r[0]?.total || 0),
  ]);

  res.json({
    success: true,
    data: {
      stats: {
        totalVolumeUsdt:  parseFloat(volume.toFixed(6)),
        balanceAvailable: parseFloat(balance.toFixed(6)),
        successfulInvoices: successCount,
        totalInvoices,
        successRate:      totalInvoices > 0 ? parseFloat(((successCount / totalInvoices) * 100).toFixed(2)) : 0,
        fees30dUsdt:      parseFloat(fees30d.toFixed(6)),
        feePercentage:    merchant.feePercentage,
        fixedFee:         merchant.fixedFee,
      },
    },
  });
}

async function setMerchantFees(req, res) {
  const data     = validate(feeSchema, req.body);
  // C2 FIX: Direct document
  const merchant = await fetchMerchant(req.params.id);

  const prev = { feePercentage: merchant.feePercentage, fixedFee: merchant.fixedFee };
  if (data.feePercentage !== undefined) merchant.feePercentage = data.feePercentage;
  if (data.fixedFee !== undefined)      merchant.fixedFee      = data.fixedFee;
  await merchant.save();

  const { AuditLog } = require('@xcg/database');
  await AuditLog.create({
    actor:      actor(req),
    action:     'merchant.fees_updated',
    resource:   'merchant',
    resourceId: String(merchant._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { prev, new: data },
  });

  res.json({ success: true, data: { feePercentage: merchant.feePercentage, fixedFee: merchant.fixedFee } });
}

async function setMerchantLimits(req, res) {
  const data     = validate(limitsSchema, req.body);
  // C2 FIX: Direct document
  const merchant = await fetchMerchant(req.params.id);

  if (data.rateLimits) {
    Object.assign(merchant.rateLimits || {}, data.rateLimits);
    merchant.markModified('rateLimits');
  }
  await merchant.save();

  const { AuditLog } = require('@xcg/database');
  await AuditLog.create({
    actor:      actor(req),
    action:     'merchant.limits_updated',
    resource:   'merchant',
    resourceId: String(merchant._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { rateLimits: data.rateLimits },
  });

  res.json({ success: true, data: { rateLimits: merchant.rateLimits } });
}

module.exports = {
  createMerchant:           asyncHandler(createMerchant),
  listMerchants:            asyncHandler(listMerchants),
  getMerchant:              asyncHandler(getMerchant),
  updateMerchant:           asyncHandler(updateMerchant),
  setMerchantStatus:        asyncHandler(setMerchantStatus),
  createApiKey:             asyncHandler(createApiKey),
  revokeApiKey:             asyncHandler(revokeApiKey),
  rotateWebhookSecret:      asyncHandler(rotateWebhookSecret),
  // Expanded admin controls
  approveMerchant:          asyncHandler(approveMerchant),
  suspendMerchant:          asyncHandler(suspendMerchant),
  getMerchantTransactions:  asyncHandler(getMerchantTransactions),
  getMerchantLedger:        asyncHandler(getMerchantLedger),
  getMerchantInvoices:      asyncHandler(getMerchantInvoices),
  getMerchantStats:         asyncHandler(getMerchantStats),
  setMerchantFees:          asyncHandler(setMerchantFees),
  setMerchantLimits:        asyncHandler(setMerchantLimits),
};
