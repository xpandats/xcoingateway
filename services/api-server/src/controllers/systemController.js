'use strict';

/**
 * @module controllers/systemController
 *
 * System Configuration & Control API.
 *
 * Provides admin endpoints to:
 *   - View and update runtime platform configuration (fees, limits, flags)
 *   - Get live health matrix of all services
 *   - Emergency controls: pause invoice creation, resume
 *
 * System config is stored in MongoDB SystemConfig collection (key-value).
 * This allows zero-downtime config changes without service restarts.
 *
 * READONLY KEYS: Some keys are read-only (e.g. network, env) — they come
 * from environment variables and cannot be changed at runtime.
 *
 * Routes (mounted at /admin/system):
 *   GET  /config              — View runtime config (sanitized)
 *   PUT  /config/:key         — Update specific config key (TOTP)
 *   GET  /health              — Full service health matrix
 *   GET  /stats               — Platform aggregate statistics
 *   POST /pause-invoices      — Pause invoice creation (TOTP)
 *   POST /resume-invoices     — Resume invoice creation (TOTP)
 *   POST /pause-withdrawals   — Pause withdrawals (TOTP) [moved here from admin.js]
 *   POST /resume-withdrawals  — Resume withdrawals (TOTP)
 */

const Joi = require('joi');
const { validate, AppError, ErrorCodes } = require('@xcg/common');
const {
  SystemConfig, AuditLog, Invoice, Transaction, Withdrawal, Merchant, Wallet, LedgerEntry,
} = require('@xcg/database');
const asyncHandler = require('../utils/asyncHandler');
const { config }   = require('../config');
const logger = require('@xcg/logger').createLogger('system-ctrl');
const cache  = require('../utils/cache');


const PAUSE_INVOICES_KEY     = 'xcg:system:invoices_paused';
const PAUSE_WITHDRAWALS_KEY  = 'xcg:system:withdrawals_paused';

// ─── Read-only config keys (sourced from ENV, not DB) ───────────────────────
const READONLY_KEYS = new Set([
  'env',
  'network',
  'mongo_uri',
  'redis_url',
  'jwt_secret',
  'master_key',
  'trongrid_api_key',
]);

// ─── GET /admin/system/config ─────────────────────────────────────────────────

async function getSystemConfig(req, res) {
  const redis = req.app.locals.redis;

  // Gap 3 fix: cache the full config list with stampede protection (10-min TTL)
  const dbConfigs = await cache.getOrSet(
    redis,
    cache.KEY.systemConfigAll(),
    cache.TTL.SYSTEM_CONFIG,
    async () => SystemConfig.find({}).select('-__v').sort({ key: 1 }).lean(),
  );

  // Merge with read-only env-sourced values (sanitized)
  const readonlyConfigs = [
    { key: 'env',        value: config.env,            readonly: true, description: 'Runtime environment' },
    { key: 'network',    value: config.tron?.network,  readonly: true, description: 'Blockchain network' },
    { key: 'networkMode',value: config.networkMode,    readonly: true, description: 'testnet/mainnet' },
  ];

  const allConfigs = [
    ...readonlyConfigs,
    ...(dbConfigs || []).map((c) => ({ ...c, readonly: READONLY_KEYS.has(c.key) })),
  ];

  res.json({
    success: true,
    data: { config: allConfigs, total: allConfigs.length },
  });
}


// G1 FIX: Import allowed key whitelist from SystemConfig model
const { ALLOWED_CONFIG_KEYS } = require('@xcg/database').SystemConfig;

// ─── PUT /admin/system/config/:key ────────────────────────────────────────────

const updateConfigSchema = Joi.object({
  value:       Joi.alternatives().try(Joi.string(), Joi.number(), Joi.boolean()).required(), // No objects — prevent injection
  description: Joi.string().max(200).optional(),
}).options({ stripUnknown: true });

async function updateSystemConfig(req, res) {
  const { key } = req.params;
  const data     = validate(updateConfigSchema, req.body);

  if (READONLY_KEYS.has(key)) {
    throw AppError.forbidden(`Config key '${key}' is read-only — it is sourced from environment variables`, ErrorCodes.CONFIG_KEY_READONLY);
  }

  // G1 FIX: Validate key against whitelist before touching DB
  if (ALLOWED_CONFIG_KEYS && !ALLOWED_CONFIG_KEYS.has(key)) {
    throw AppError.badRequest(`Config key '${key}' is not in the allowed key whitelist. Update ALLOWED_CONFIG_KEYS in SystemConfig model first.`);
  }

  // G8 FIX: updatedBy is now required — use req.user.userId (set by authenticate middleware)
  const actorId = req.user.userId || String(req.user._id);

  const updated = await SystemConfig.findOneAndUpdate(
    { key },
    {
      $set: {
        value:       data.value,
        description: data.description,
        updatedBy:   actorId,
      },
    },
    { upsert: true, new: true, setDefaultsOnInsert: true, runValidators: true },
  );

  await AuditLog.create({
    actor:      actorId,
    action:     'system.config_updated',
    resource:   'system_config',
    resourceId: key,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { key, newValue: data.value },
  });

  // Gap 3 fix: bust the config cache so next read is fresh
  await cache.invalidateSystemConfig(req.app.locals.redis, key);

  logger.warn('SystemCtrl: config key updated', {
    key,
    newValue: data.value,
    adminId:  actorId,
  });

  res.json({ success: true, data: { config: updated } });
}


// ─── GET /admin/system/health ──────────────────────────────────────────────────

async function getSystemHealth(req, res) {
  const redis = req.app.locals.redis;
  const checks = {};

  // MongoDB
  try {
    const { isDBConnected } = require('@xcg/database');
    checks.mongodb = { status: isDBConnected() ? 'healthy' : 'down', latencyMs: null };
  } catch (e) {
    checks.mongodb = { status: 'error', message: e.message };
  }

  // Redis
  try {
    if (redis) {
      const start = Date.now();
      await redis.ping();
      checks.redis = { status: 'healthy', latencyMs: Date.now() - start };
    } else {
      checks.redis = { status: 'unknown', message: 'No Redis client in app context' };
    }
  } catch (e) {
    checks.redis = { status: 'down', message: e.message };
  }

  // Withdrawal pause status
  let withdrawalsPaused = false;
  let invoicesPaused    = false;
  if (redis) {
    try {
      withdrawalsPaused = !!(await redis.get(PAUSE_WITHDRAWALS_KEY));
      invoicesPaused    = !!(await redis.get(PAUSE_INVOICES_KEY));
    } catch { /* noop */ }
  }

  // Queue depths via BullMQ internal Redis key patterns.
  // BullMQ uses sorted sets (ZSET) not lists (LIST), so we use ZCARD not LLEN.
  // Key format: {queueName}:wait  — jobs waiting to be processed
  //             {queueName}:delayed — jobs scheduled for future processing
  // Queue names from QUEUES constants (xcg:payment:created, etc.)
  const queueDepths = {};
  if (redis) {
    const bullQueues = [
      { name: 'payment:created',      key: 'xcg:payment:created' },
      { name: 'transaction:detected', key: 'xcg:transaction:detected' },
      { name: 'payment:confirmed',    key: 'xcg:payment:confirmed' },
      { name: 'signing:request',      key: 'xcg:signing:request' },
      { name: 'withdrawal:eligible',  key: 'xcg:withdrawal:eligible' },
      { name: 'dead:letter',          key: 'xcg:dead:letter' },
    ];
    for (const q of bullQueues) {
      try {
        // BullMQ wait queue = sorted set with key {queueName}:wait
        const waiting = await redis.zcard(`${q.key}:wait`);
        const delayed = await redis.zcard(`${q.key}:delayed`);
        const failed  = await redis.zcard(`${q.key}:failed`);
        queueDepths[q.name] = { waiting, delayed, failed };
      } catch { /* skip — queue may not exist yet */ }
    }
  }

  const [
    pendingInvoices,
    pendingWithdrawals,
    activeWallets,
  ] = await Promise.all([
    Invoice.countDocuments({ status: { $in: ['initiated', 'pending', 'hash_found', 'confirming'] } }).catch(() => null),
    Withdrawal.countDocuments({ status: 'requested' }).catch(() => null),
    Wallet.countDocuments({ isActive: true }).catch(() => null),
  ]);

  const overallStatus = Object.values(checks).every((c) => c.status === 'healthy') ? 'healthy' : 'degraded';

  res.json({
    success: true,
    data: {
      status:   overallStatus,
      services: checks,
      platform: {
        withdrawalsPaused,
        invoicesPaused,
        pendingInvoices,
        pendingWithdrawals,
        activeWallets,
      },
      queues:   queueDepths,
      checkedAt: new Date().toISOString(),
    },
  });
}

// ─── GET /admin/system/stats ───────────────────────────────────────────────────

async function getSystemStats(req, res) {
  const now   = new Date();
  const last7d = new Date(now - 7 * 86_400_000);
  const last30d = new Date(now - 30 * 86_400_000);

  const [
    totalMerchants,
    activeMerchants,
    approvedMerchants,
    totalInvoices,
    successfulInvoices,
    totalWithdrawals,
    completedWithdrawals,
    volume7d,
    volume30d,
    pendingWithdrawalValue,
  ] = await Promise.all([
    Merchant.countDocuments({}),
    Merchant.countDocuments({ isActive: true }),
    Merchant.countDocuments({ isApproved: true }),
    Invoice.countDocuments({}),
    Invoice.countDocuments({ status: { $in: ['confirmed', 'success'] } }),
    Withdrawal.countDocuments({}),
    Withdrawal.countDocuments({ status: 'completed' }),
    Transaction.aggregate([
      { $match: { status: 'confirmed', createdAt: { $gte: last7d } } },
      { $group: { _id: null, total: { $sum: '$amount' } } },
    ]).then((r) => r[0]?.total || 0),
    Transaction.aggregate([
      { $match: { status: 'confirmed', createdAt: { $gte: last30d } } },
      { $group: { _id: null, total: { $sum: '$amount' } } },
    ]).then((r) => r[0]?.total || 0),
    Withdrawal.aggregate([
      { $match: { status: { $in: ['requested', 'pending_approval', 'processing'] } } },
      { $group: { _id: null, total: { $sum: '$amount' } } },
    ]).then((r) => r[0]?.total || 0),
  ]);

  res.json({
    success: true,
    data: {
      merchants: { total: totalMerchants, active: activeMerchants, approved: approvedMerchants },
      invoices:  { total: totalInvoices, successful: successfulInvoices },
      withdrawals: { total: totalWithdrawals, completed: completedWithdrawals, pending: pendingWithdrawalValue },
      volume:    { last7dUsdt: volume7d, last30dUsdt: volume30d },
      generatedAt: now.toISOString(),
    },
  });
}

// ─── Emergency Controls ───────────────────────────────────────────────────────

async function pauseInvoices(req, res) {
  const redis = req.app.locals.redis;
  if (!redis) throw AppError.serviceUnavailable('Redis unavailable');

  await redis.set(PAUSE_INVOICES_KEY, '1');

  await AuditLog.create({
    actor:      req.user.userId || String(req.user._id),
    action:     'system.invoices_paused',
    resource:   'system',
    resourceId: 'global',
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { reason: req.body?.reason || 'Admin emergency action' },
  });

  logger.warn('SystemCtrl: INVOICE CREATION PAUSED', { adminId: req.user.userId || String(req.user._id) });
  res.json({ success: true, message: 'Invoice creation paused. No new invoices will be created until resumed.' });
}

async function resumeInvoices(req, res) {
  const redis = req.app.locals.redis;
  if (!redis) throw AppError.serviceUnavailable('Redis unavailable');

  await redis.del(PAUSE_INVOICES_KEY);

  await AuditLog.create({
    actor:      req.user.userId || String(req.user._id),
    action:     'system.invoices_resumed',
    resource:   'system',
    resourceId: 'global',
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
  });

  logger.info('SystemCtrl: invoice creation resumed', { adminId: req.user.userId || String(req.user._id) });
  res.json({ success: true, message: 'Invoice creation resumed.' });
}

async function pauseWithdrawals(req, res) {
  const redis = req.app.locals.redis;
  if (!redis) throw AppError.serviceUnavailable('Redis unavailable');

  await redis.set(PAUSE_WITHDRAWALS_KEY, '1');

  await AuditLog.create({
    actor:      req.user.userId || String(req.user._id),
    action:     'system.withdrawals_paused',
    resource:   'system',
    resourceId: 'global',
    ipAddress:  req.ip,
    metadata:   { reason: req.body?.reason || 'Manual admin pause' },
    outcome:    'success',
    timestamp:  new Date(),
  });

  logger.warn('SystemCtrl: WITHDRAWALS PAUSED', { adminId: req.user.userId || String(req.user._id) });
  res.json({ success: true, message: 'Withdrawals paused platform-wide.' });
}

async function resumeWithdrawals(req, res) {
  const redis = req.app.locals.redis;
  if (!redis) throw AppError.serviceUnavailable('Redis unavailable');

  await redis.del(PAUSE_WITHDRAWALS_KEY);

  await AuditLog.create({
    actor:      req.user.userId || String(req.user._id),
    action:     'system.withdrawals_resumed',
    resource:   'system',
    resourceId: 'global',
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
  });

  logger.info('SystemCtrl: withdrawals resumed', { adminId: req.user.userId || String(req.user._id) });
  res.json({ success: true, message: 'Withdrawals resumed.' });
}

module.exports = {
  getSystemConfig:     asyncHandler(getSystemConfig),
  updateSystemConfig:  asyncHandler(updateSystemConfig),
  getSystemHealth:     asyncHandler(getSystemHealth),
  getSystemStats:      asyncHandler(getSystemStats),
  pauseInvoices:       asyncHandler(pauseInvoices),
  resumeInvoices:      asyncHandler(resumeInvoices),
  pauseWithdrawals:    asyncHandler(pauseWithdrawals),
  resumeWithdrawals:   asyncHandler(resumeWithdrawals),
};
