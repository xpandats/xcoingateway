'use strict';

/**
 * @module controllers/disputeController
 *
 * Dispute Management — Admin and Support facing.
 *
 * FUND FREEZE (CRITICAL):
 *   When a dispute is opened, funds are atomically moved from:
 *     merchant_receivable → dispute_hold
 *   This ensures the disputed amount cannot be withdrawn while under review.
 *
 * RESOLUTION:
 *   - resolved_refund:    funds in dispute_hold are marked for refund to customer
 *   - resolved_no_refund: funds in dispute_hold released back to merchant_receivable
 */

const mongoose   = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const Joi        = require('joi');
const { Dispute, Invoice, LedgerEntry, Merchant } = require('@xcg/database');
const { AppError, validate } = require('@xcg/common');
const { DISPUTE_STATUS, LEDGER_ACCOUNTS } = require('@xcg/common').constants;
const asyncHandler = require('../utils/asyncHandler');
const { createLogger } = require('@xcg/logger');

const logger = createLogger('dispute-ctrl');

// ── Validators ────────────────────────────────────────────────────────────────

const openSchema = Joi.object({
  invoiceId:     Joi.string().hex().length(24).required(),
  reason:        Joi.string().trim().min(20).max(2000).required(),
  evidence:      Joi.array().items(Joi.string().uri({ scheme: ['https'] })).max(10).optional(),
  merchantDeadlineHours: Joi.number().integer().min(24).max(168).default(72),
}).options({ stripUnknown: true });

const resolveSchema = Joi.object({
  resolution: Joi.string().valid('refund', 'no_refund').required(),
  notes:      Joi.string().trim().max(2000).optional(),
  refundAmount: Joi.number().min(0).optional(), // Partial refund amount (if different from full)
}).options({ stripUnknown: true });

// ── Handler: Open Dispute ─────────────────────────────────────────────────────

async function openDispute(req, res) {
  const data = validate(openSchema, req.body);

  const invoice = await Invoice.findById(data.invoiceId).lean();
  if (!invoice) throw AppError.notFound('Invoice not found');
  if (!['confirmed', 'success'].includes(invoice.status)) {
    throw AppError.conflict('Disputes can only be opened on confirmed payments');
  }

  // Check for existing open dispute on this invoice
  const existing = await Dispute.findOne({
    invoiceId: invoice._id,
    status: { $nin: ['resolved_refund', 'resolved_no_refund', 'closed'] },
  }).lean();
  if (existing) throw AppError.conflict('An open dispute already exists for this invoice');

  const session = await mongoose.startSession();
  let dispute;

  try {
    await session.withTransaction(async () => {
      // 1. Check merchant has sufficient balance in receivable
      const balanceCheck = await LedgerEntry.aggregate([
        { $match: { merchantId: invoice.merchantId, account: LEDGER_ACCOUNTS.MERCHANT_RECEIVABLE } },
        { $group: { _id: null, net: { $sum: { $cond: [{ $eq: ['$type', 'credit'] }, '$amount', { $multiply: ['$amount', -1] }] } } } },
      ]);
      const merchantBalance = balanceCheck[0]?.net || 0;
      const disputeAmount   = invoice.netAmount || invoice.baseAmount;

      if (merchantBalance < disputeAmount) {
        throw AppError.conflict('Merchant has insufficient balance to place dispute hold');
      }

      // 2. Create dispute record
      const disputeId = `dsp_${uuidv4().replace(/-/g, '')}`;
      const holdId    = `led_${uuidv4().replace(/-/g, '')}`;
      const debitId   = `led_${uuidv4().replace(/-/g, '')}`;

      // 3. Atomic double-entry: debit merchant_receivable, credit dispute_hold
      await LedgerEntry.create([
        {
          entryId:            debitId,
          account:            LEDGER_ACCOUNTS.MERCHANT_RECEIVABLE,
          type:               'debit',
          amount:             disputeAmount,
          currency:           'USDT',
          merchantId:         invoice.merchantId,
          invoiceId:          invoice._id,
          counterpartEntryId: holdId,
          description:        `Dispute hold — ${disputeId}`,
          idempotencyKey:     `ledger:dispute:open:${disputeId}`,
          balanceAfter:       0,
        },
        {
          entryId:            holdId,
          account:            LEDGER_ACCOUNTS.DISPUTE_HOLD,
          type:               'credit',
          amount:             disputeAmount,
          currency:           'USDT',
          merchantId:         invoice.merchantId,
          invoiceId:          invoice._id,
          counterpartEntryId: debitId,
          description:        `Dispute hold credit — ${disputeId}`,
          idempotencyKey:     `ledger:dispute:hold:${disputeId}`,
          balanceAfter:       0,
        },
      ], { session });

      // 4. Create dispute
      [dispute] = await Dispute.create([{
        disputeId,
        invoiceId:         invoice._id,
        merchantId:        invoice.merchantId,
        transactionId:     invoice.txHash ? null : null, // Linked when available
        amount:            disputeAmount,
        status:            DISPUTE_STATUS.OPENED,
        reason:            data.reason,
        evidence:          data.evidence || [],
        openedBy:          req.user.id,
        merchantDeadline:  new Date(Date.now() + (data.merchantDeadlineHours * 3600000)),
        holdLedgerEntryId: holdId,
        holdAmount:        disputeAmount,
        fundsHeld:         true,
        notes:             `Dispute opened by ${req.user.email} at ${new Date().toISOString()}`,
      }], { session });
    });

    logger.info('disputeController: dispute opened + funds frozen', {
      disputeId: dispute.disputeId, invoiceId: data.invoiceId,
      merchantId: String(invoice.merchantId), amount: dispute.amount,
      actor: req.user.id,
    });

    res.status(201).json({ success: true, data: { dispute } });

  } catch (err) {
    logger.error('disputeController: failed to open dispute', { error: err.message });
    throw err;
  } finally {
    await session.endSession();
  }
}

// ── Handler: Resolve Dispute ──────────────────────────────────────────────────

async function resolveDispute(req, res) {
  const data = validate(resolveSchema, req.body);

  const dispute = await Dispute.findById(req.params.id);
  if (!dispute) throw AppError.notFound('Dispute not found');

  if (['resolved_refund', 'resolved_no_refund', 'closed'].includes(dispute.status)) {
    throw AppError.conflict('Dispute is already resolved');
  }
  if (!dispute.fundsHeld) {
    throw AppError.conflict('No funds are held for this dispute');
  }

  const session = await mongoose.startSession();

  try {
    await session.withTransaction(async () => {
      const releaseId = `led_${uuidv4().replace(/-/g, '')}`;
      const holdReleaseId = `led_${uuidv4().replace(/-/g, '')}`;
      const refundAmount  = data.refundAmount || dispute.holdAmount;

      if (data.resolution === 'refund') {
        // Release from dispute_hold — mark as refund pending (actual on-chain refund handled separately)
        await LedgerEntry.create([
          {
            entryId:            holdReleaseId,
            account:            LEDGER_ACCOUNTS.DISPUTE_HOLD,
            type:               'debit',
            amount:             dispute.holdAmount,
            currency:           'USDT',
            merchantId:         dispute.merchantId,
            invoiceId:          dispute.invoiceId,
            counterpartEntryId: releaseId,
            description:        `Dispute resolved — refund — ${dispute.disputeId}`,
            idempotencyKey:     `ledger:dispute:refund:${dispute.disputeId}`,
            balanceAfter:       0,
          },
          {
            entryId:            releaseId,
            account:            LEDGER_ACCOUNTS.SYSTEM_RESERVE,
            type:               'credit',
            amount:             refundAmount,
            currency:           'USDT',
            merchantId:         dispute.merchantId,
            invoiceId:          dispute.invoiceId,
            counterpartEntryId: holdReleaseId,
            description:        `Dispute refund reserve — ${dispute.disputeId}`,
            idempotencyKey:     `ledger:dispute:reserve:${dispute.disputeId}`,
            balanceAfter:       0,
          },
        ], { session });

        dispute.status = DISPUTE_STATUS.RESOLVED_REFUND;

      } else {
        // no_refund: release funds back to merchant_receivable
        await LedgerEntry.create([
          {
            entryId:            holdReleaseId,
            account:            LEDGER_ACCOUNTS.DISPUTE_HOLD,
            type:               'debit',
            amount:             dispute.holdAmount,
            currency:           'USDT',
            merchantId:         dispute.merchantId,
            invoiceId:          dispute.invoiceId,
            counterpartEntryId: releaseId,
            description:        `Dispute closed — no refund — releasing to merchant — ${dispute.disputeId}`,
            idempotencyKey:     `ledger:dispute:release:${dispute.disputeId}`,
            balanceAfter:       0,
          },
          {
            entryId:            releaseId,
            account:            LEDGER_ACCOUNTS.MERCHANT_RECEIVABLE,
            type:               'credit',
            amount:             dispute.holdAmount,
            currency:           'USDT',
            merchantId:         dispute.merchantId,
            invoiceId:          dispute.invoiceId,
            counterpartEntryId: holdReleaseId,
            description:        `Dispute release — no refund — ${dispute.disputeId}`,
            idempotencyKey:     `ledger:dispute:mr-restore:${dispute.disputeId}`,
            balanceAfter:       0,
          },
        ], { session });

        dispute.status = DISPUTE_STATUS.RESOLVED_NO_REFUND;
      }

      dispute.fundsHeld   = false;
      dispute.resolvedBy  = req.user.id;
      dispute.resolvedAt  = new Date();
      dispute.resolution  = data.resolution;
      dispute.notes       = (dispute.notes || '') + `\n[Resolved by ${req.user.email} at ${new Date().toISOString()}: ${data.resolution}${data.notes ? ' — ' + data.notes : ''}]`;
      await dispute.save({ session });
    });

    logger.info('disputeController: dispute resolved', {
      disputeId: dispute.disputeId, resolution: data.resolution, actor: req.user.id,
    });

    res.json({ success: true, data: { dispute } });

  } catch (err) {
    logger.error('disputeController: failed to resolve dispute', { error: err.message });
    throw err;
  } finally {
    await session.endSession();
  }
}

// ── Handler: List / Get Dispute ───────────────────────────────────────────────

async function listDisputes(req, res) {
  const { page = 1, limit = 20, status, merchantId } = req.query;
  const skip   = (Number(page) - 1) * Number(limit);
  const filter = {};
  if (status)     filter.status     = status;
  if (merchantId) filter.merchantId = merchantId;

  const [disputes, total] = await Promise.all([
    Dispute.find(filter).sort({ createdAt: -1 }).skip(skip).limit(Number(limit)).lean(),
    Dispute.countDocuments(filter),
  ]);

  res.json({ success: true, data: { disputes, pagination: { page: Number(page), limit: Number(limit), total } } });
}

async function getDispute(req, res) {
  const dispute = await Dispute.findById(req.params.id).lean();
  if (!dispute) throw AppError.notFound('Dispute not found');
  res.json({ success: true, data: { dispute } });
}

module.exports = {
  openDispute:    asyncHandler(openDispute),
  resolveDispute: asyncHandler(resolveDispute),
  listDisputes:   asyncHandler(listDisputes),
  getDispute:     asyncHandler(getDispute),
};
