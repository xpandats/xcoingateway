'use strict';

/**
 * @module controllers/keyRotationController
 *
 * Key Rotation Audit — Read-only admin endpoints for viewing rotation history.
 *
 * SECURITY:
 *   - All routes: authenticate + authorize('admin') + require2FA + adminIpWhitelist
 *   - READ-ONLY — no mutations here (writes come from merchantService, authService, etc.)
 *   - Rotation IDs validated before DB query
 *   - Pagination limits enforced
 *   - Never exposes rawKeyId, actual key values, or sensitive rotation details
 *
 * KeyRotationLog is written by:
 *   - merchantService.createApiKey()     → merchant_api_key
 *   - merchantService.revokeApiKey()     → merchant_api_key (revocation)
 *   - merchantService.rotateWebhookSecret() → merchant_webhook
 *   - (Future) authService JWT rotation  → jwt_secret
 *   - (Future) key vault rotation        → master_encryption_key
 *
 * Routes (mounted at /admin/key-rotations):
 *   GET    /stats              — Rotation statistics (by type, by status, last 30d)
 *   GET    /                  — List rotation events (filterable)
 *   GET    /:rotationId       — Get single rotation detail
 */

const Joi           = require('joi');
const { KeyRotationLog } = require('@xcg/database');
const { AppError, validate } = require('@xcg/common');
const asyncHandler  = require('../utils/asyncHandler');
const { createLogger } = require('@xcg/logger');

const logger = createLogger('key-rotation-ctrl');

// ─── Joi Schemas ──────────────────────────────────────────────────────────────

const listSchema = Joi.object({
  keyType:    Joi.string().valid(
    'jwt_secret', 'master_encryption_key', 'merchant_api_key',
    'merchant_webhook', 'internal_service_token', 'queue_hmac_secret',
  ).optional(),
  status:     Joi.string().valid('initiated', 'in_progress', 'completed', 'failed', 'rolled_back').optional(),
  merchantId: Joi.string().hex().length(24).optional(),
  page:       Joi.number().integer().min(1).max(1000).default(1),
  limit:      Joi.number().integer().min(1).max(100).default(20),
}).options({ stripUnknown: true });

// ─── GET /admin/key-rotations/stats ───────────────────────────────────────────

async function getRotationStats(req, res) {
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  const [totalCount, last30DaysCount, byType, byStatus, lastRotation] = await Promise.all([
    KeyRotationLog.countDocuments(),
    KeyRotationLog.countDocuments({ createdAt: { $gte: thirtyDaysAgo } }),
    KeyRotationLog.aggregate([
      {
        $group: {
          _id:         '$keyType',
          count:       { $sum: 1 },
          lastRotated: { $max: '$createdAt' },
        },
      },
      { $sort: { lastRotated: -1 } },
    ]),
    KeyRotationLog.aggregate([
      { $group: { _id: '$status', count: { $sum: 1 } } },
    ]),
    KeyRotationLog.findOne()
      .sort({ createdAt: -1 })
      .select('rotationId keyType status createdAt completedAt initiatedBy reason')
      .lean(),
  ]);

  res.json({
    success: true,
    data: {
      totalRotations: totalCount,
      last30Days:     last30DaysCount,
      lastRotation,
      byType: byType.reduce((acc, r) => {
        acc[r._id] = { count: r.count, lastRotated: r.lastRotated };
        return acc;
      }, {}),
      byStatus: byStatus.reduce((acc, r) => {
        acc[r._id] = r.count;
        return acc;
      }, {}),
    },
  });
}

// ─── GET /admin/key-rotations ─────────────────────────────────────────────────

async function listRotations(req, res) {
  const { keyType, status, merchantId, page, limit } = validate(listSchema, req.query);
  const filter = {};
  if (keyType)    filter.keyType    = keyType;
  if (status)     filter.status     = status;
  if (merchantId) filter.merchantId = merchantId;

  const skip = (page - 1) * limit;
  const [rotations, total] = await Promise.all([
    KeyRotationLog.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      // Never return raw key data — only audit fields
      .select('rotationId keyType merchantId serviceName oldKeyId newKeyId status startedAt completedAt failedAt durationMs initiatedBy reason gracePeriodMs graceExpiresAt walletsReEncrypted totalWallets createdAt')
      .lean(),
    KeyRotationLog.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data: {
      rotations,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    },
  });
}

// ─── GET /admin/key-rotations/:rotationId ─────────────────────────────────────

async function getRotation(req, res) {
  const { rotationId } = req.params;
  if (!rotationId || !/^rot_[a-zA-Z0-9]{24}$/.test(rotationId)) {
    throw AppError.badRequest('Invalid rotation ID format');
  }

  const rotation = await KeyRotationLog.findOne({ rotationId })
    .select('-__v')
    .lean();
  if (!rotation) throw AppError.notFound('Key rotation record not found');

  res.json({ success: true, data: { rotation } });
}

module.exports = {
  getRotationStats: asyncHandler(getRotationStats),
  listRotations:    asyncHandler(listRotations),
  getRotation:      asyncHandler(getRotation),
};
