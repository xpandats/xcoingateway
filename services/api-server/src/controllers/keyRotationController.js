'use strict';

/**
 * @module controllers/keyRotationController
 *
 * Key Rotation Audit — Admin endpoints for viewing key rotation history.
 *
 * KeyRotationLog is populated by:
 *   - merchantController (when API key is rotated/revoked)
 *   - authService (when JWT secrets are rotated — future)
 *   - walletService (when master encryption key is rotated — future)
 *
 * Routes (mounted at /admin/key-rotations):
 *   GET    /                   — List rotation events
 *   GET    /:rotationId        — Get rotation detail
 *   GET    /stats              — Rotation statistics
 */

const { KeyRotationLog, AuditLog } = require('@xcg/database');
const { AppError } = require('@xcg/common');
const asyncHandler = require('../utils/asyncHandler');
const logger = require('@xcg/logger').createLogger('key-rotation-ctrl');

// ─── GET /admin/key-rotations ─────────────────────────────────────────────────

async function listRotations(req, res) {
  const { keyType, status, merchantId, page = 1, limit = 20 } = req.query;
  const filter = {};
  if (keyType)    filter.keyType = keyType;
  if (status)     filter.status = status;
  if (merchantId) filter.merchantId = merchantId;

  const skip = (Math.max(1, parseInt(page, 10)) - 1) * parseInt(limit, 10);
  const [rotations, total] = await Promise.all([
    KeyRotationLog.find(filter).sort({ createdAt: -1 }).skip(skip).limit(parseInt(limit, 10)).lean(),
    KeyRotationLog.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data: { rotations, pagination: { page: parseInt(page, 10), limit: parseInt(limit, 10), total, pages: Math.ceil(total / parseInt(limit, 10)) } },
  });
}

// ─── GET /admin/key-rotations/:rotationId ─────────────────────────────────────

async function getRotation(req, res) {
  const rotation = await KeyRotationLog.findOne({ rotationId: req.params.rotationId }).lean();
  if (!rotation) throw AppError.notFound('Key rotation record not found');
  res.json({ success: true, data: rotation });
}

// ─── GET /admin/key-rotations/stats ───────────────────────────────────────────

async function getRotationStats(req, res) {
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  const [total, last30Days, byType, byStatus] = await Promise.all([
    KeyRotationLog.countDocuments(),
    KeyRotationLog.countDocuments({ createdAt: { $gte: thirtyDaysAgo } }),
    KeyRotationLog.aggregate([
      { $group: { _id: '$keyType', count: { $sum: 1 }, lastRotated: { $max: '$createdAt' } } },
    ]),
    KeyRotationLog.aggregate([
      { $group: { _id: '$status', count: { $sum: 1 } } },
    ]),
  ]);

  const lastRotation = await KeyRotationLog.findOne()
    .sort({ createdAt: -1 })
    .select('rotationId keyType createdAt status')
    .lean();

  res.json({
    success: true,
    data: {
      totalRotations: total,
      last30Days,
      lastRotation,
      byType:   byType.reduce((acc, r) => { acc[r._id] = { count: r.count, lastRotated: r.lastRotated }; return acc; }, {}),
      byStatus: byStatus.reduce((acc, r) => { acc[r._id] = r.count; return acc; }, {}),
    },
  });
}

module.exports = {
  listRotations:    asyncHandler(listRotations),
  getRotation:      asyncHandler(getRotation),
  getRotationStats: asyncHandler(getRotationStats),
};
