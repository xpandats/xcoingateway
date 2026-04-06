'use strict';

/**
 * @module controllers/withdrawalController
 *
 * Withdrawal Controller — Merchant-facing withdrawal request API.
 *
 * Routes (merchant API — HMAC authenticated):
 *   POST /api/v1/withdrawals       — Request a withdrawal
 *   GET  /api/v1/withdrawals       — List withdrawals for merchant
 *   GET  /api/v1/withdrawals/:id   — Get withdrawal status
 */

const Joi = require('joi');
const { v4: uuidv4 } = require('uuid');
const mongoose = require('mongoose');
const { validate, AppError, money } = require('@xcg/common');
const { Withdrawal, LedgerEntry, Wallet, Merchant } = require('@xcg/database');
const asyncHandler = require('../utils/asyncHandler');
const { config }   = require('../config');

const logger = require('@xcg/logger').createLogger('withdrawal-ctrl');

// Withdrawal eligible publisher — injected at startup by server.js (same pattern as paymentCreatedPublisher)
// Publishing to WITHDRAWAL_ELIGIBLE triggers the withdrawal engine to pick up and sign the request.
let withdrawalEligiblePublisher = null;
function setWithdrawalEligiblePublisher(publisher) {
  withdrawalEligiblePublisher = publisher;
}

const PAUSE_WITHDRAWALS_KEY = 'xcg:system:withdrawals_paused';

const createSchema = Joi.object({
  amount:         Joi.number().min(0.01).max(1000).precision(6).required(),
  toAddress:      Joi.string().pattern(/^T[1-9A-HJ-NP-Za-km-z]{33}$/).optional(),
  idempotencyKey: Joi.string().uuid().optional(),
}).options({ stripUnknown: true });

const paginationSchema = Joi.object({
  page:   Joi.number().integer().min(1).default(1),
  limit:  Joi.number().integer().min(1).max(100).default(20),
  status: Joi.string().optional(),
}).options({ stripUnknown: true });

// ─── POST /api/v1/withdrawals ────────────────────────────────────────────────

async function createWithdrawal(req, res) {
  const data       = validate(createSchema, req.body);
  const merchant   = req.merchant;
  const redisClient = req.app.locals.redis;

  // Check system-wide pause (set by reconciliation service on mismatch)
  if (redisClient) {
    const paused = await redisClient.get(PAUSE_WITHDRAWALS_KEY);
    if (paused) {
      throw AppError.serviceUnavailable('Withdrawals are temporarily paused — system maintenance');
    }
  }

  // Withdrawal address: use request body or merchant's saved address
  const toAddress = data.toAddress || merchant.withdrawalAddress;
  if (!toAddress) {
    throw AppError.badRequest('Withdrawal address not set — configure in merchant settings');
  }

  // Validate destination isn't one of our own wallets
  const isOwnWallet = await Wallet.exists({ address: toAddress, isActive: true });
  if (isOwnWallet) {
    throw AppError.badRequest('Cannot withdraw to a platform wallet address');
  }

  // Per-tx limit
  const perTxLimit = config.wallet.perTxWithdrawalLimit;
  if (data.amount > perTxLimit) {
    throw AppError.badRequest(`Amount exceeds maximum withdrawal limit of ${perTxLimit} USDT per transaction`);
  }

  // Daily cap check
  const dailyCap  = config.wallet.dailyWithdrawalCap;
  const startOfDay = new Date();
  startOfDay.setHours(0, 0, 0, 0);

  const dailyResult = await Withdrawal.aggregate([
    {
      $match: {
        merchantId: new mongoose.Types.ObjectId(String(merchant._id)),
        status:     { $in: ['processing', 'broadcast', 'confirmed', 'completed'] },
        createdAt:  { $gte: startOfDay },
      },
    },
    { $group: { _id: null, total: { $sum: '$amount' } } },
  ]);
  const dailyUsed = dailyResult[0]?.total || 0;

  if (dailyUsed + data.amount > dailyCap) {
    throw AppError.badRequest(
      `Daily cap of ${dailyCap} USDT reached. Used: ${dailyUsed.toFixed(2)} USDT. Resets at midnight UTC.`,
    );
  }

  // Cooling-off period check (1 hour after last deposit)
  const cooldownMs = config.wallet.withdrawalCooldownMs;
  const lastDeposit = await LedgerEntry.findOne({
    merchantId: new mongoose.Types.ObjectId(String(merchant._id)),
    account:    'merchant_receivable',
    type:       'credit',
  }).sort({ createdAt: -1 }).select('createdAt').lean();

  if (lastDeposit) {
    const ageMs = Date.now() - lastDeposit.createdAt.getTime();
    if (ageMs < cooldownMs) {
      const remainingMin = Math.ceil((cooldownMs - ageMs) / 60_000);
      throw AppError.badRequest(
        `Withdrawal cooling-off period active. Please wait ${remainingMin} minute(s) before withdrawing.`,
      );
    }
  }

  // Ledger balance check
  const balResult = await LedgerEntry.aggregate([
    { $match: { merchantId: new mongoose.Types.ObjectId(String(merchant._id)), account: 'merchant_receivable' } },
    {
      $group: {
        _id:    null,
        credits:{ $sum: { $cond: [{ $eq: ['$type', 'credit'] }, '$amount', 0] } },
        debits: { $sum: { $cond: [{ $eq: ['$type', 'debit'] },  '$amount', 0] } },
      },
    },
  ]);
  const balance = balResult[0] ? balResult[0].credits - balResult[0].debits : 0;

  if (balance < data.amount) {
    throw AppError.badRequest(
      `Insufficient balance. Available: ${balance.toFixed(6)} USDT, Requested: ${data.amount} USDT`,
    );
  }

  // High-value threshold → requires admin approval
  const requiresApproval = data.amount > config.wallet.highValueThreshold;

  // Create withdrawal (idempotent)
  const idempotencyKey = data.idempotencyKey || `wdl:${uuidv4()}`;
  let withdrawal;

  const session = await mongoose.startSession();
  try {
    await session.withTransaction(async () => {
      // Idempotency: check existing
      const existing = await Withdrawal.findOne({ idempotencyKey }).lean();
      if (existing) {
        withdrawal = existing;
        return;
      }

      const wdlId   = `wdl_${uuidv4().replace(/-/g, '')}`;
      const creditId = `led_${uuidv4().replace(/-/g, '')}`;
      const debitId  = `led_${uuidv4().replace(/-/g, '')}`;

      [withdrawal] = await Withdrawal.create([{
        withdrawalId:    wdlId,
        merchantId:      merchant._id,
        amount:          data.amount,
        netAmount:       data.amount, // No additional withdrawal fee in MVP
        currency:        'USDT',
        network:         'tron',
        toAddress,
        status:          requiresApproval ? 'pending_approval' : 'requested',
        requiresApproval,
        idempotencyKey,
      }], { session });

      // Ledger debit (reserve the funds)
      await LedgerEntry.create([
        {
          entryId:            debitId,
          account:            'merchant_receivable',
          type:               'debit',
          amount:             data.amount,
          currency:           'USDT',
          merchantId:         merchant._id,
          withdrawalId:       withdrawal._id,
          counterpartEntryId: creditId,
          description:        `Withdrawal requested — ${wdlId}`,
          idempotencyKey:     `ledger:wdl-debit:${idempotencyKey}`,
          balanceAfter:       money.round(balance - data.amount, 6),
        },
        {
          entryId:            creditId,
          account:            'merchant_withdrawal',
          type:               'credit',
          amount:             data.amount,
          currency:           'USDT',
          merchantId:         merchant._id,
          withdrawalId:       withdrawal._id,
          counterpartEntryId: debitId,
          description:        `Withdrawal credit — ${wdlId}`,
          idempotencyKey:     `ledger:wdl-credit:${idempotencyKey}`,
          balanceAfter:       0,
        },
      ], { session });
    });
  } catch (err) {
    logger.error('WithdrawalController: DB tx failed', { error: err.message });
    throw err;
  } finally {
    await session.endSession();
  }

  logger.info('WithdrawalController: withdrawal created', {
    withdrawalId: withdrawal.withdrawalId,
    merchantId:   String(merchant._id),
    amount:       data.amount,
    requiresApproval,
  });

  // Publish to withdrawal engine queue (non-blocking — failure logged, not thrown)
  // Skip if pending admin approval — engine should not process until approved
  if (!requiresApproval && withdrawalEligiblePublisher) {
    withdrawalEligiblePublisher.publish(
      {
        merchantId:      String(merchant._id),
        amount:          String(withdrawal.amount),
        idempotencyKey,  // Engine uses this to find the existing withdrawal record
      },
      idempotencyKey,  // BullMQ job ID — deduplication
    ).catch((err) => logger.error('WithdrawalController: failed to publish to WITHDRAWAL_ELIGIBLE', {
      withdrawalId: withdrawal.withdrawalId, error: err.message,
    }));
  }

  res.status(201).json({
    success: true,
    data: {
      withdrawal: {
        withdrawalId:    withdrawal.withdrawalId,
        status:          withdrawal.status,
        amount:          withdrawal.amount,
        currency:        withdrawal.currency,
        toAddress:       withdrawal.toAddress,
        requiresApproval:withdrawal.requiresApproval,
        createdAt:       withdrawal.createdAt,
        message:         requiresApproval
          ? 'Withdrawal pending admin approval due to amount threshold'
          : 'Withdrawal submitted for processing',
      },
    },
  });
}

// ─── GET /api/v1/withdrawals ─────────────────────────────────────────────────

async function listWithdrawals(req, res) {
  const { page = 1, limit = 20, status } = validate(paginationSchema, req.query);
  const merchant = req.merchant;

  const filter = { merchantId: merchant._id };
  if (status) filter.status = status;

  const [withdrawals, total] = await Promise.all([
    Withdrawal.find(filter)
      .select('-lastError -__v')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(),
    Withdrawal.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data: {
      withdrawals,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    },
  });
}

// ─── GET /api/v1/withdrawals/:id ─────────────────────────────────────────────

async function getWithdrawal(req, res) {
  const merchant    = req.merchant;
  const withdrawal  = await Withdrawal.findOne({
    withdrawalId: req.params.id,
    merchantId:   merchant._id,
  }).select('-lastError -__v').lean();

  if (!withdrawal) throw AppError.notFound('Withdrawal not found');

  res.json({ success: true, data: { withdrawal } });
}

// ─── GET /api/v1/balance ─────────────────────────────────────────────────────

async function getBalance(req, res) {
  const merchant = req.merchant;

  const result = await LedgerEntry.aggregate([
    { $match: { merchantId: new mongoose.Types.ObjectId(String(merchant._id)), account: 'merchant_receivable' } },
    {
      $group: {
        _id:    null,
        credits:{ $sum: { $cond: [{ $eq: ['$type', 'credit'] }, '$amount', 0] } },
        debits: { $sum: { $cond: [{ $eq: ['$type', 'debit'] },  '$amount', 0] } },
      },
    },
  ]);

  const credits  = result[0]?.credits || 0;
  const debits   = result[0]?.debits  || 0;
  const available = money.round(credits - debits, 6);

  res.json({
    success: true,
    data: {
      balance: {
        available,
        currency: 'USDT',
        network:  'tron',
      },
    },
  });
}

module.exports = {
  createWithdrawal: asyncHandler(createWithdrawal),
  listWithdrawals:  asyncHandler(listWithdrawals),
  getWithdrawal:    asyncHandler(getWithdrawal),
  getBalance:       asyncHandler(getBalance),
  setWithdrawalEligiblePublisher,
};
