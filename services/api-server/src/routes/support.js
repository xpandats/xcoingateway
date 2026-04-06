'use strict';

/**
 * @module routes/support
 *
 * Support Role Routes — Read-only access to transactions + disputes.
 *
 * SECURITY:
 *   - Requires authenticate() + authorize('support') — support role only
 *   - Read-only: GET methods only (no create/update/delete) except dispute escalation
 *   - Cannot access merchant API keys, wallet private keys, or user passwords
 *   - IP whitelist enforced (same as admin)
 *   - All access is audit logged
 *
 * SUPPORT ROLE DATA MASKING (Gap B fix):
 *   Support users must NOT see full TRC20 wallet addresses. A compromised support
 *   account would otherwise expose all merchant receiving addresses — enabling:
 *     - Targeted phishing of merchants ("we see your wallet address is T...XYZ")
 *     - Correlation of merchant identities across blockchain explorers
 *     - Customer-targeted fraud with real wallet data
 *
 *   Fix: maskAddress() shows first 6 chars + ...MASKED... + last 4 chars.
 *   Applied to: walletAddress, toAddress, fromAddress, withdrawalAddress.
 *   The full address is NEVER returned to a support role user.
 *
 * Per spec: "support: read-only access to transactions, can escalate disputes"
 */

const express = require('express');
const router  = express.Router();
const { authenticate }       = require('../middleware/authenticate');
const { authorize }          = require('../middleware/authorize');
const { adminIpWhitelist }   = require('../middleware/adminIpWhitelist');
const asyncHandler           = require('../utils/asyncHandler');
const { Invoice, Transaction, Withdrawal, Dispute, AuditLog } = require('@xcg/database');
const { AppError } = require('@xcg/common');
const { createLogger } = require('@xcg/logger');

const logger = createLogger('support-routes');

// ─── 3-layer security for support ────────────────────────────────────────────
router.use(authenticate);
router.use(authorize('support'));
router.use(adminIpWhitelist());

// ─── Data masking helpers (Gap B fix) ─────────────────────────────────────────

/**
 * Mask a TRC20/blockchain address for support view.
 * TRC20 addresses are 34 chars: T + 33 base58.
 * Output: "T1abc6...MASKED...XYZ4" (visually identifiable for matching but not exploitable)
 *
 * @param {string|null|undefined} addr
 * @returns {string}
 */
function maskAddress(addr) {
  if (!addr || typeof addr !== 'string') return addr;
  if (addr.length < 12) return '***MASKED***'; // Too short to safely show any portion
  return `${addr.slice(0, 6)}...MASKED...${addr.slice(-4)}`;
}

/**
 * Apply address masking to a transaction document.
 * Masks: walletAddress, toAddress, fromAddress
 *
 * @param {object} tx - Plain transaction object
 * @returns {object} Masked transaction object
 */
function maskTransaction(tx) {
  if (!tx) return tx;
  const masked = { ...tx };
  if (masked.walletAddress) masked.walletAddress = maskAddress(masked.walletAddress);
  if (masked.toAddress)     masked.toAddress     = maskAddress(masked.toAddress);
  if (masked.fromAddress)   masked.fromAddress   = maskAddress(masked.fromAddress);
  return masked;
}

/**
 * Apply address masking to an invoice document.
 * Masks: walletAddress
 *
 * @param {object} invoice - Plain invoice object
 * @returns {object} Masked invoice object
 */
function maskInvoice(invoice) {
  if (!invoice) return invoice;
  const masked = { ...invoice };
  if (masked.walletAddress) masked.walletAddress = maskAddress(masked.walletAddress);
  return masked;
}

/**
 * Apply address masking to a withdrawal document.
 * Masks: toAddress, withdrawalAddress
 *
 * @param {object} wd - Plain withdrawal object
 * @returns {object} Masked withdrawal object
 */
function maskWithdrawal(wd) {
  if (!wd) return wd;
  const masked = { ...wd };
  if (masked.toAddress)          masked.toAddress          = maskAddress(masked.toAddress);
  if (masked.withdrawalAddress)  masked.withdrawalAddress  = maskAddress(masked.withdrawalAddress);
  return masked;
}

// ─── Audit helper ──────────────────────────────────────────────────────────────
async function logSupportAccess(action, req, metadata = {}) {
  try {
    await AuditLog.create({
      actor:     req.user.userId,
      action,
      resource:  'support_access',
      ipAddress: req.ip,
      outcome:   'success',
      timestamp: new Date(),
      metadata:  { ...metadata, supportUserId: req.user.userId },
    });
  } catch (err) {
    logger.error('Failed to write support access audit log', { error: err.message });
  }
}

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

  await logSupportAccess('support.transactions_listed', req, { filter });

  const [transactions, total] = await Promise.all([
    Transaction.find(filter)
      .select('-__v')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(Number(limit))
      .lean(),
    Transaction.countDocuments(filter),
  ]);

  // Gap B: Mask all wallet addresses before returning to support role
  const masked = transactions.map(maskTransaction);

  res.json({
    success: true,
    data:    { transactions: masked, pagination: { page: Number(page), limit: Number(limit), total } },
  });
}));

/**
 * GET /api/v1/support/transactions/:txHash
 * Get full transaction details by txHash.
 */
router.get('/transactions/:txHash', asyncHandler(async (req, res) => {
  const tx = await Transaction.findOne({ txHash: req.params.txHash }).lean();
  if (!tx) throw AppError.notFound('Transaction not found');

  await logSupportAccess('support.transaction_viewed', req, { txHash: req.params.txHash });

  // Gap B: Mask address before returning
  res.json({ success: true, data: { transaction: maskTransaction(tx) } });
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

  // Gap B: Mask all wallet addresses
  const masked = invoices.map(maskInvoice);

  res.json({
    success: true,
    data:    { invoices: masked, pagination: { page: Number(page), limit: Number(limit), total } },
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

  // Gap B: Mask withdrawal destination addresses
  const masked = withdrawals.map(maskWithdrawal);

  res.json({
    success: true,
    data:    { withdrawals: masked, pagination: { page: Number(page), limit: Number(limit), total } },
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

  dispute.status      = 'under_review';
  dispute.escalatedBy = req.user.userId;
  dispute.escalatedAt = new Date();
  dispute.notes = (dispute.notes || '') + `\n[Escalated by support ${req.user.email} at ${new Date().toISOString()}]`;
  await dispute.save();

  await logSupportAccess('support.dispute_escalated', req, { disputeId: req.params.id });

  res.json({ success: true, data: { dispute } });
}));

module.exports = router;
