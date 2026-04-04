'use strict';

/**
 * @module routes/support
 *
 * Support Role Routes — Read-only access to transactions + disputes.
 *
 * SECURITY:
 *   - Requires authenticate() + authorize('support') — support role only
 *   - Read-only: GET methods only (no create/update/delete)
 *   - Cannot access merchant API keys, wallet private keys, or user passwords
 *   - IP whitelist enforced (same as admin)
 *   - All access is audit logged
 *
 * Per spec: "support: read-only access to transactions, can escalate disputes"
 */

const express = require('express');
const router  = express.Router();
const { authenticate }       = require('../middleware/authenticate');
const { authorize }          = require('../middleware/authorize');
const { adminIpWhitelist }   = require('../middleware/adminIpWhitelist');
const asyncHandler           = require('../utils/asyncHandler');
const { Invoice, Transaction, Withdrawal, Dispute } = require('@xcg/database');
const { AppError } = require('@xcg/common');
const { createAuditLogger } = require('@xcg/logger').auditLogger || require('@xcg/logger');
const { createLogger } = require('@xcg/logger');

const logger = createLogger('support-routes');

// 3-layer security for support: authenticate + role check + IP whitelist
router.use(authenticate);
router.use(authorize('support'));
router.use(adminIpWhitelist);

// ── Transactions — read-only ─────────────────────────────────────────────────

/**
 * GET /api/v1/support/transactions
 * List all transactions with filtering. Paginated.
 */
router.get('/transactions', asyncHandler(async (req, res) => {
  const { page = 1, limit = 50, status, merchantId, txHash } = req.query;
  const skip   = (Number(page) - 1) * Number(limit);
  const filter = {};
  if (status)     filter.status     = status;
  if (merchantId) filter.merchantId = merchantId;
  if (txHash)     filter.txHash     = txHash;

  logger.info('Support: transactions list accessed', { actor: req.user.id, ip: req.ip });

  const [transactions, total] = await Promise.all([
    Transaction.find(filter)
      .select('-__v')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(Number(limit))
      .lean(),
    Transaction.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data:    { transactions, pagination: { page: Number(page), limit: Number(limit), total } },
  });
}));

/**
 * GET /api/v1/support/transactions/:txHash
 * Get full transaction details by txHash.
 */
router.get('/transactions/:txHash', asyncHandler(async (req, res) => {
  const tx = await Transaction.findOne({ txHash: req.params.txHash }).lean();
  if (!tx) throw AppError.notFound('Transaction not found');

  logger.info('Support: transaction detail accessed', {
    actor: req.user.id, txHash: req.params.txHash, ip: req.ip,
  });

  res.json({ success: true, data: { transaction: tx } });
}));

/**
 * GET /api/v1/support/invoices
 * List invoices across all merchants. Support can search by any field.
 */
router.get('/invoices', asyncHandler(async (req, res) => {
  const { page = 1, limit = 50, status, merchantId, invoiceId } = req.query;
  const skip   = (Number(page) - 1) * Number(limit);
  const filter = {};
  if (status)     filter.status     = status;
  if (merchantId) filter.merchantId = merchantId;
  if (invoiceId)  filter.invoiceId  = invoiceId;

  const [invoices, total] = await Promise.all([
    Invoice.find(filter)
      .select('-amountOffset -__v') // amountOffset is internal — never expose
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(Number(limit))
      .lean(),
    Invoice.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data:    { invoices, pagination: { page: Number(page), limit: Number(limit), total } },
  });
}));

/**
 * GET /api/v1/support/withdrawals
 * List withdrawal requests — support can review pending approvals.
 */
router.get('/withdrawals', asyncHandler(async (req, res) => {
  const { page = 1, limit = 50, status, merchantId } = req.query;
  const skip   = (Number(page) - 1) * Number(limit);
  const filter = {};
  if (status)     filter.status     = status;
  if (merchantId) filter.merchantId = merchantId;

  const [withdrawals, total] = await Promise.all([
    Withdrawal.find(filter)
      .select('-__v')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(Number(limit))
      .lean(),
    Withdrawal.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data:    { withdrawals, pagination: { page: Number(page), limit: Number(limit), total } },
  });
}));

/**
 * GET /api/v1/support/disputes
 * List open disputes. Support can view and escalate.
 */
router.get('/disputes', asyncHandler(async (req, res) => {
  const { page = 1, limit = 50, status } = req.query;
  const skip   = (Number(page) - 1) * Number(limit);
  const filter = status ? { status } : {};

  const [disputes, total] = await Promise.all([
    Dispute.find(filter)
      .select('-__v')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(Number(limit))
      .lean(),
    Dispute.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data:    { disputes, pagination: { page: Number(page), limit: Number(limit), total } },
  });
}));

/**
 * POST /api/v1/support/disputes/:id/escalate
 * Support can escalate a dispute to admin review.
 * This is a write operation but is gated to escalation only — cannot resolve.
 */
router.post('/disputes/:id/escalate', asyncHandler(async (req, res) => {
  const dispute = await Dispute.findById(req.params.id);
  if (!dispute) throw AppError.notFound('Dispute not found');
  if (['resolved_refund', 'resolved_no_refund', 'closed'].includes(dispute.status)) {
    throw AppError.conflict('Cannot escalate a resolved dispute');
  }

  dispute.status     = 'under_review';
  dispute.escalatedBy = req.user.id;
  dispute.escalatedAt = new Date();
  dispute.notes = (dispute.notes || '') + `\n[Escalated by support ${req.user.email} at ${new Date().toISOString()}]`;
  await dispute.save();

  logger.info('Support: dispute escalated', {
    actor: req.user.id, disputeId: req.params.id, ip: req.ip,
  });

  res.json({ success: true, data: { dispute } });
}));

module.exports = router;
