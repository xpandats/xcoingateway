'use strict';

/**
 * @module controllers/adminController
 *
 * Admin Dashboard API — Platform-wide metrics and controls.
 *
 * Routes (all require: authenticate + authorize('admin') + adminIpWhitelist):
 *   GET  /admin/dashboard              — Platform KPIs
 *   GET  /admin/transactions           — Transaction ledger view
 *   GET  /admin/withdrawals/pending    — Pending approval queue
 *   PUT  /admin/withdrawals/:id/approve — Approve/reject withdrawal
 *   GET  /admin/audit-log              — Audit trail
 *   POST /admin/system/pause-withdrawals  — Emergency pause
 *   POST /admin/system/resume-withdrawals — Resume
 */

const Joi = require('joi');
const mongoose = require('mongoose');
const {
  Invoice, Transaction, Withdrawal, LedgerEntry, Wallet, Merchant, AuditLog,
} = require('@xcg/database');
const { validate, AppError } = require('@xcg/common');
const { INVOICE_STATUS, WITHDRAWAL_STATUS } = require('@xcg/common').constants;
const asyncHandler = require('../utils/asyncHandler');
const { config }   = require('../config');

const logger = require('@xcg/logger').createLogger('admin-ctrl');

const PAUSE_WITHDRAWALS_KEY = 'xcg:system:withdrawals_paused';

// ─── Validation ──────────────────────────────────────────────────────────────

const approveSchema = Joi.object({
  action:      Joi.string().valid('approve', 'reject').required(),
  reviewNotes: Joi.string().max(500).optional().allow(''),
}).options({ stripUnknown: true });

const auditLogSchema = Joi.object({
  page:     Joi.number().integer().min(1).default(1),
  limit:    Joi.number().integer().min(1).max(100).default(50),
  actor:    Joi.string().optional(),
  action:   Joi.string().optional(),
  from:     Joi.date().iso().optional(),
  to:       Joi.date().iso().optional(),
}).options({ stripUnknown: true });

const txListSchema = Joi.object({
  page:     Joi.number().integer().min(1).default(1),
  limit:    Joi.number().integer().min(1).max(100).default(20),
  status:   Joi.string().optional(),
  from:     Joi.date().iso().optional(),
  to:       Joi.date().iso().optional(),
}).options({ stripUnknown: true });

// ─── Dashboard KPIs ─────────────────────────────────────────────────────────

async function getDashboard(req, res) {
  const last24h  = new Date(Date.now() - 86_400_000);
  const last7d   = new Date(Date.now() - 7 * 86_400_000);

  const [
    totalVolume24h,
    totalVolume7d,
    confirmedToday,
    pendingInvoices,
    activeWallets,
    pendingWithdrawals,
    merchantCount,
    platformFees24h,
  ] = await Promise.all([
    // Volume last 24h (confirmed txns)
    Transaction.aggregate([
      { $match: { status: 'confirmed', createdAt: { $gte: last24h } } },
      { $group: { _id: null, total: { $sum: '$amount' } } },
    ]).then((r) => r[0]?.total || 0),

    // Volume last 7 days
    Transaction.aggregate([
      { $match: { status: 'confirmed', createdAt: { $gte: last7d } } },
      { $group: { _id: null, total: { $sum: '$amount' } } },
    ]).then((r) => r[0]?.total || 0),

    // Confirmed invoices today
    Invoice.countDocuments({ status: INVOICE_STATUS.CONFIRMED, confirmedAt: { $gte: last24h } }),

    // Active pending invoices
    Invoice.countDocuments({
      status: { $in: [INVOICE_STATUS.PENDING, INVOICE_STATUS.HASH_FOUND] },
      expiresAt: { $gt: new Date() },
    }),

    // Active hot wallets
    Wallet.countDocuments({ isActive: true }),

    // Pending withdrawal approvals
    Withdrawal.countDocuments({ status: WITHDRAWAL_STATUS.PENDING_APPROVAL }),

    // Total merchants
    Merchant.countDocuments({ isActive: true }),

    // Platform fees collected last 24h
    LedgerEntry.aggregate([
      { $match: { account: 'platform_fee', type: 'credit', createdAt: { $gte: last24h } } },
      { $group: { _id: null, total: { $sum: '$amount' } } },
    ]).then((r) => r[0]?.total || 0),
  ]);

  // Get system pause status
  const redis = req.app.locals.redis;
  let withdrawalsPaused = false;
  if (redis) {
    withdrawalsPaused = !!(await redis.get(PAUSE_WITHDRAWALS_KEY));
  }

  res.json({
    success: true,
    data: {
      kpis: {
        volumeUsdt24h:      parseFloat(totalVolume24h.toFixed(6)),
        volumeUsdt7d:       parseFloat(totalVolume7d.toFixed(6)),
        confirmedPayments24h: confirmedToday,
        pendingInvoices,
        activeWallets,
        pendingWithdrawalApprovals: pendingWithdrawals,
        activeMerchants:    merchantCount,
        platformFees24h:    parseFloat(platformFees24h.toFixed(6)),
      },
      system: {
        withdrawalsPaused,
        network:    config.tron.network,
        networkMode:config.networkMode,
        environment:config.env,
      },
      generatedAt: new Date().toISOString(),
    },
  });
}

// ─── Transactions ────────────────────────────────────────────────────────────

async function listTransactions(req, res) {
  const { page, limit, status, from, to } = validate(txListSchema, req.query);

  const filter = {};
  if (status) filter.status = status;
  if (from || to) {
    filter.createdAt = {};
    if (from) filter.createdAt.$gte = new Date(from);
    if (to)   filter.createdAt.$lte = new Date(to);
  }

  const [transactions, total] = await Promise.all([
    Transaction.find(filter)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .populate('matchedInvoiceId', 'invoiceId merchantId status amount')
      .lean(),
    Transaction.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data: { transactions, pagination: { page, limit, total, pages: Math.ceil(total / limit) } },
  });
}

// ─── Withdrawal Approval ─────────────────────────────────────────────────────

async function listPendingWithdrawals(req, res) {
  const page  = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 20;

  const [withdrawals, total] = await Promise.all([
    Withdrawal.find({ status: WITHDRAWAL_STATUS.PENDING_APPROVAL })
      .sort({ createdAt: 1 }) // Oldest first (FIFO)
      .skip((page - 1) * limit)
      .limit(limit)
      .populate('merchantId', 'businessName email')
      .lean(),
    Withdrawal.countDocuments({ status: WITHDRAWAL_STATUS.PENDING_APPROVAL }),
  ]);

  res.json({
    success: true,
    data: { withdrawals, pagination: { page, limit, total, pages: Math.ceil(total / limit) } },
  });
}

async function approveWithdrawal(req, res) {
  const { action, reviewNotes } = validate(approveSchema, req.body);

  const withdrawal = await Withdrawal.findById(req.params.id);
  if (!withdrawal) throw AppError.notFound('Withdrawal not found');

  if (withdrawal.status !== WITHDRAWAL_STATUS.PENDING_APPROVAL) {
    throw AppError.conflict(
      `Withdrawal is in '${withdrawal.status}' state — only pending_approval withdrawals can be approved/rejected`,
    );
  }

  if (action === 'approve') {
    withdrawal.status     = WITHDRAWAL_STATUS.APPROVED;
    withdrawal.approvedBy = req.user._id;
    withdrawal.approvedAt = new Date();
    withdrawal.reviewNotes = reviewNotes || '';
  } else {
    withdrawal.status     = WITHDRAWAL_STATUS.REJECTED;
    withdrawal.rejectedBy = req.user._id;
    withdrawal.rejectedAt = new Date();
    withdrawal.reviewNotes = reviewNotes || '';
  }

  await withdrawal.save();

  // Audit log
  await AuditLog.create({
    actor:      String(req.user._id),
    action:     action === 'approve' ? 'withdrawal.approved' : 'withdrawal.rejected',
    resource:   'withdrawal',
    resourceId: String(withdrawal._id),
    ipAddress:  req.ip,
    metadata: {
      withdrawalId: withdrawal.withdrawalId,
      amount:       withdrawal.amount,
      merchantId:   String(withdrawal.merchantId),
      reviewNotes:  reviewNotes || '',
    },
    outcome:   'success',
    timestamp: new Date(),
  });

  logger.info(`AdminCtrl: withdrawal ${action}d`, {
    withdrawalId: withdrawal.withdrawalId,
    amount:       withdrawal.amount,
    adminId:      String(req.user._id),
  });

  res.json({
    success: true,
    data: {
      withdrawal: {
        _id:           withdrawal._id,
        withdrawalId:  withdrawal.withdrawalId,
        status:        withdrawal.status,
        amount:        withdrawal.amount,
        merchantId:    withdrawal.merchantId,
        reviewNotes:   withdrawal.reviewNotes,
        updatedAt:     withdrawal.updatedAt,
      },
      action,
    },
  });
}

// ─── Audit Log ───────────────────────────────────────────────────────────────

async function getAuditLog(req, res) {
  const { page, limit, actor, action, from, to } = validate(auditLogSchema, req.query);

  const filter = {};
  if (actor)  filter.actor  = actor;
  if (action) filter.action = action;
  if (from || to) {
    filter.timestamp = {};
    if (from) filter.timestamp.$gte = new Date(from);
    if (to)   filter.timestamp.$lte = new Date(to);
  }

  const [entries, total] = await Promise.all([
    AuditLog.find(filter)
      .sort({ timestamp: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(),
    AuditLog.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data: { entries, pagination: { page, limit, total, pages: Math.ceil(total / limit) } },
  });
}

// ─── System Controls ─────────────────────────────────────────────────────────

async function pauseWithdrawals(req, res) {
  const redis = req.app.locals.redis;
  if (!redis) throw AppError.serviceUnavailable('Redis unavailable');

  await redis.set(PAUSE_WITHDRAWALS_KEY, '1'); // No expiry — must be manually resumed

  await AuditLog.create({
    actor:      String(req.user._id),
    action:     'system.withdrawals_paused',
    resource:   'system',
    resourceId: 'global',
    ipAddress:  req.ip,
    metadata:   { reason: req.body?.reason || 'Manual admin pause' },
    outcome:    'success',
    timestamp:  new Date(),
  });

  logger.warn('AdminCtrl: WITHDRAWALS PAUSED', { adminId: String(req.user._id), ip: req.ip });

  res.json({ success: true, message: 'Withdrawals paused platform-wide. All new requests will be rejected until resumed.' });
}

async function resumeWithdrawals(req, res) {
  const redis = req.app.locals.redis;
  if (!redis) throw AppError.serviceUnavailable('Redis unavailable');

  await redis.del(PAUSE_WITHDRAWALS_KEY);

  await AuditLog.create({
    actor:      String(req.user._id),
    action:     'system.withdrawals_resumed',
    resource:   'system',
    resourceId: 'global',
    ipAddress:  req.ip,
    metadata:   {},
    outcome:    'success',
    timestamp:  new Date(),
  });

  logger.info('AdminCtrl: withdrawals resumed', { adminId: String(req.user._id) });

  res.json({ success: true, message: 'Withdrawals resumed.' });
}

// ─── Exports ─────────────────────────────────────────────────────────────────

module.exports = {
  getDashboard:          asyncHandler(getDashboard),
  listTransactions:      asyncHandler(listTransactions),
  listPendingWithdrawals:asyncHandler(listPendingWithdrawals),
  approveWithdrawal:     asyncHandler(approveWithdrawal),
  getAuditLog:           asyncHandler(getAuditLog),
  pauseWithdrawals:      asyncHandler(pauseWithdrawals),
  resumeWithdrawals:     asyncHandler(resumeWithdrawals),
};
