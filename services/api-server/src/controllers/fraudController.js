'use strict';

/**
 * @module controllers/fraudController
 *
 * Admin fraud & risk management endpoints.
 * All routes require full 4-layer admin auth + TOTP for mutations.
 *
 * Endpoints:
 *   GET    /admin/fraud/blacklist        — List blacklisted wallets (paginated)
 *   POST   /admin/fraud/blacklist        — Add wallet to blacklist [TOTP]
 *   DELETE /admin/fraud/blacklist/:id    — Deactivate (soft-delete) blacklist entry [TOTP]
 *   GET    /admin/fraud/events           — List fraud events (paginated, filterable)
 *   GET    /admin/fraud/stats            — Fraud summary statistics
 */

const Joi = require('joi');
const { validate, AppError } = require('@xcg/common');
const { BlacklistedWallet, FraudEvent, AuditLog } = require('@xcg/database');
const { BLACKLIST_REASON } = require('@xcg/database/src/models/BlacklistedWallet');
const { FRAUD_EVENT_TYPE, FRAUD_ACTION } = require('@xcg/database/src/models/FraudEvent');
const { AUDIT_ACTIONS } = require('@xcg/common').constants;
const logger = require('@xcg/logger').createLogger('fraud-ctrl');

// ─── Validation Schemas ───────────────────────────────────────────────────────

const addBlacklistSchema = Joi.object({
  address: Joi.string().trim().min(10).max(100).required(),
  network: Joi.string().valid('tron', 'eth', 'bnb').default('tron'),
  reason:  Joi.string().valid(...Object.values(BLACKLIST_REASON)).required(),
  notes:   Joi.string().trim().max(1000).optional().allow(''),
  linkedTxHash: Joi.string().optional().allow('', null),
  expiresAt:    Joi.date().iso().min('now').optional().allow(null), // null = permanent
}).options({ stripUnknown: true });

const listSchema = Joi.object({
  page:    Joi.number().integer().min(1).default(1),
  limit:   Joi.number().integer().min(1).max(100).default(20),
  network: Joi.string().optional(),
  reason:  Joi.string().valid(...Object.values(BLACKLIST_REASON)).optional(),
  active:  Joi.boolean().default(true),
}).options({ stripUnknown: true });

const eventListSchema = Joi.object({
  page:       Joi.number().integer().min(1).default(1),
  limit:      Joi.number().integer().min(1).max(100).default(50),
  action:     Joi.string().valid(...Object.values(FRAUD_ACTION)).optional(),
  eventType:  Joi.string().valid(...Object.values(FRAUD_EVENT_TYPE)).optional(),
  merchantId: Joi.string().optional(),
  minScore:   Joi.number().min(0).max(100).optional(),
}).options({ stripUnknown: true });

// ─── Handlers ─────────────────────────────────────────────────────────────────

/**
 * GET /admin/fraud/blacklist
 * List all blacklisted wallets with pagination and filtering.
 */
async function listBlacklist(req, res) {
  const { page, limit, network, reason, active } = validate(listSchema, req.query);

  const filter = { isActive: active };
  if (network) filter.network = network;
  if (reason)  filter.reason = reason;

  const [entries, total] = await Promise.all([
    BlacklistedWallet
      .find(filter)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .populate('addedBy', 'email role')
      .lean(),
    BlacklistedWallet.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data:    entries,
    pagination: { page, limit, total, pages: Math.ceil(total / limit) },
  });
}

/**
 * POST /admin/fraud/blacklist
 * Add a wallet address to the blacklist. Requires TOTP re-confirmation.
 */
async function addToBlacklist(req, res) {
  const data = validate(addBlacklistSchema, req.body);

  // Idempotent: if already blacklisted and active, return existing entry
  const existing = await BlacklistedWallet.findOne({
    address:  data.address.toLowerCase(),
    network:  data.network,
    isActive: true,
  }).lean();

  if (existing) {
    return res.json({
      success:  true,
      created:  false,
      message:  'Address is already on the blacklist',
      data:     existing,
    });
  }

  const entry = await BlacklistedWallet.create({
    address:  data.address.toLowerCase(),
    network:  data.network,
    reason:   data.reason,
    notes:    data.notes   || '',
    addedBy:  req.user._id,
    expiresAt:data.expiresAt || null,
    linkedTxHash: data.linkedTxHash || null,
    isActive: true,
  });

  // Audit log
  await AuditLog.create({
    actor:    req.user._id,
    actorRole:req.user.role,
    action:   AUDIT_ACTIONS.TX_MANUAL_REVIEW,  // Closest relevant action
    ipAddress:req.ip,
    userAgent:req.headers['user-agent'],
    details: {
      action:'blacklist_add', address: data.address,
      reason: data.reason, network: data.network,
    },
  }).catch(() => {}); // Never crash on audit log failure

  logger.warn('fraudController: wallet added to blacklist', {
    address: data.address, reason: data.reason, addedBy: String(req.user._id),
  });

  res.status(201).json({ success: true, created: true, data: entry });
}

/**
 * DELETE /admin/fraud/blacklist/:id
 * Deactivate a blacklist entry (soft delete — record is preserved for audit).
 * Requires TOTP re-confirmation.
 */
async function removeFromBlacklist(req, res) {
  const entry = await BlacklistedWallet.findById(req.params.id);
  if (!entry) throw new AppError(404, 'Blacklist entry not found', 'NOT_FOUND');
  if (!entry.isActive) throw new AppError(400, 'Entry is already inactive', 'ALREADY_INACTIVE');

  // Soft delete: mark inactive, never physically remove
  entry.isActive = false;
  await entry.save();

  await AuditLog.create({
    actor:    req.user._id,
    actorRole:req.user.role,
    action:   AUDIT_ACTIONS.TX_MANUAL_REVIEW,
    ipAddress:req.ip,
    userAgent:req.headers['user-agent'],
    details: { action: 'blacklist_remove', entryId: req.params.id, address: entry.address },
  }).catch(() => {});

  logger.info('fraudController: blacklist entry deactivated', {
    entryId: req.params.id, address: entry.address, deactivatedBy: String(req.user._id),
  });

  res.json({ success: true, message: 'Blacklist entry deactivated (record preserved)' });
}

/**
 * GET /admin/fraud/events
 * List fraud events with filtering by action, type, merchant, min risk score.
 */
async function listFraudEvents(req, res) {
  const { page, limit, action, eventType, merchantId, minScore } = validate(eventListSchema, req.query);

  const filter = {};
  if (action)     filter.action    = action;
  if (eventType)  filter.eventType = eventType;
  if (merchantId) filter.merchantId = merchantId;
  if (minScore != null)  filter.riskScore = { $gte: minScore };

  const [events, total] = await Promise.all([
    FraudEvent
      .find(filter)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(),
    FraudEvent.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data:    events,
    pagination: { page, limit, total, pages: Math.ceil(total / limit) },
  });
}

/**
 * GET /admin/fraud/stats
 * Aggregate fraud statistics for dashboard widgets.
 */
async function getFraudStats(req, res) {
  const since24h = new Date(Date.now() - 86400_000);
  const since7d  = new Date(Date.now() - 7 * 86400_000);

  const [
    blockedToday,
    flaggedToday,
    blockedWeek,
    blacklistActive,
    topRiskEvents,
    byType,
  ] = await Promise.all([
    FraudEvent.countDocuments({ action: FRAUD_ACTION.BLOCKED, createdAt: { $gte: since24h } }),
    FraudEvent.countDocuments({ action: FRAUD_ACTION.FLAGGED, createdAt: { $gte: since24h } }),
    FraudEvent.countDocuments({ action: FRAUD_ACTION.BLOCKED, createdAt: { $gte: since7d } }),
    BlacklistedWallet.countDocuments({ isActive: true }),
    FraudEvent
      .find({ riskScore: { $gte: 70 }, createdAt: { $gte: since7d } })
      .sort({ riskScore: -1 })
      .limit(10)
      .lean(),
    FraudEvent.aggregate([
      { $match: { createdAt: { $gte: since7d } } },
      { $group: { _id: '$eventType', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]),
  ]);

  res.json({
    success: true,
    data: {
      blockedToday,
      flaggedToday,
      blockedWeek,
      blacklistActiveCount: blacklistActive,
      topRiskEvents,
      eventsByType: byType,
    },
  });
}

module.exports = {
  listBlacklist,
  addToBlacklist,
  removeFromBlacklist,
  listFraudEvents,
  getFraudStats,
};
