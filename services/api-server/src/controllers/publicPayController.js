'use strict';

/**
 * @module controllers/publicPayController
 *
 * Public Payment Status API — No authentication required.
 *
 * These endpoints power the customer-facing payment page.
 * They return ONLY the minimum info needed for a customer to:
 *   1. Know where to send payment (wallet address + amount)
 *   2. Track payment status in real time
 *   3. Get QR code data
 *
 * STRICT DATA MINIMISATION:
 *   - Never expose merchant business name or internal IDs
 *   - Never expose feeAmount, netAmount (merchant's financial data)
 *   - Never expose metadata (merchant's order data)
 *   - Never expose unique decimal offset algorithm details
 *   - Rate limited aggressively (no auth = most abusable)
 *
 * Routes (mounted at /api/v1/pay, no auth):
 *   GET  /:invoiceId         — Get public payment info
 *   GET  /:invoiceId/status  — Lightweight status poll
 *   GET  /:invoiceId/qr      — QR code data
 */

const Joi = require('joi');
const crypto = require('crypto');
const { validate, AppError } = require('@xcg/common');
const { Invoice, PaymentSession } = require('@xcg/database');
const { INVOICE_STATUS } = require('@xcg/common').constants;
const asyncHandler = require('../utils/asyncHandler');
const logger = require('@xcg/logger').createLogger('public-pay');

// Fields NEVER returned on public routes (strict deny-list)
const PUBLIC_INVOICE_SELECT = [
  'invoiceId',
  'status',
  'uniqueAmount',
  'currency',
  'network',
  'walletAddress',
  'expiresAt',
  'confirmedAt',
  'txHash',
  'createdAt',
].join(' ');

// Terminals states (no more polling needed)
const TERMINAL_STATUSES = new Set([
  INVOICE_STATUS.CONFIRMED,
  INVOICE_STATUS.SUCCESS,
  INVOICE_STATUS.EXPIRED,
  INVOICE_STATUS.FAILED,
  INVOICE_STATUS.CANCELLED,
]);

// Cache-control for terminal states (immutable after terminal)
function setCacheHeaders(res, status) {
  if (TERMINAL_STATUSES.has(status)) {
    res.set('Cache-Control', 'public, max-age=300'); // 5 min cache on settled invoices
  } else {
    res.set('Cache-Control', 'no-store, no-cache');  // Never cache pending states
  }
}

// ─── GET /api/v1/pay/:invoiceId ──────────────────────────────────────────────

async function getPublicInvoice(req, res) {
  const { invoiceId } = req.params;

  // Basic invoice ID format check (prevents DB query on garbage input)
  if (!invoiceId || !(/^inv_[a-zA-Z0-9]{12,32}$/.test(invoiceId))) {
    throw AppError.notFound('Invoice not found');
  }

  const invoice = await Invoice.findOne({ invoiceId })
    .select(PUBLIC_INVOICE_SELECT)
    .lean();

  if (!invoice) throw AppError.notFound('Invoice not found');

  setCacheHeaders(res, invoice.status);

  // Build customer-facing display status
  const displayStatusMap = {
    [INVOICE_STATUS.INITIATED]:  'awaiting_payment',
    [INVOICE_STATUS.PENDING]:    'awaiting_payment',
    [INVOICE_STATUS.HASH_FOUND]: 'payment_detected',
    [INVOICE_STATUS.CONFIRMING]: 'confirming',
    [INVOICE_STATUS.CONFIRMED]:  'payment_confirmed',
    [INVOICE_STATUS.SUCCESS]:    'payment_confirmed',
    [INVOICE_STATUS.EXPIRED]:    'expired',
    [INVOICE_STATUS.FAILED]:     'failed',
    [INVOICE_STATUS.CANCELLED]:  'cancelled',
    [INVOICE_STATUS.UNDERPAID]:  'payment_issue',
    [INVOICE_STATUS.OVERPAID]:   'payment_issue',
  };

  const isExpired     = invoice.expiresAt && new Date() > new Date(invoice.expiresAt);
  const isTerminal    = TERMINAL_STATUSES.has(invoice.status);
  const timeRemaining = !isTerminal && invoice.expiresAt
    ? Math.max(0, Math.floor((new Date(invoice.expiresAt) - Date.now()) / 1000))
    : 0;

  // Create or update PaymentSession for analytics (non-blocking)
  const sessionId = `ps_${crypto.randomBytes(12).toString('hex')}`;
  const visitorIpHash = req.ip ? crypto.createHash('sha256').update(req.ip).digest('hex').slice(0, 16) : null;

  PaymentSession.findOneAndUpdate(
    { invoiceId: invoice._id, status: 'active' },
    {
      $setOnInsert: {
        sessionId,
        invoiceId:     invoice._id,
        merchantId:    invoice.merchantId || null,
        displayAmount: invoice.uniqueAmount,
        displayAddress:invoice.walletAddress,
        currency:      invoice.currency,
        network:       invoice.network || 'tron',
        qrData:        `tron:${invoice.walletAddress}?amount=${invoice.uniqueAmount}&token=USDT`,
        expiresAt:     invoice.expiresAt,
        timeoutMs:     invoice.expiresAt ? Math.max(0, new Date(invoice.expiresAt) - Date.now()) : 0,
        visitorIpHash,
        visitorAgent:  (req.headers['user-agent'] || '').slice(0, 200),
      },
      $inc:  { pageViews: 1 },
      $set:  { lastViewedAt: new Date() },
    },
    { upsert: true, new: true },
  ).catch(() => {});

  res.json({
    success: true,
    data: {
      invoiceId:       invoice.invoiceId,
      status:          invoice.status,
      displayStatus:   displayStatusMap[invoice.status] || invoice.status,
      isTerminal,
      isExpired,
      amountUsdt:      invoice.uniqueAmount,
      currency:        invoice.currency,
      network:         invoice.network,
      walletAddress:   invoice.walletAddress,
      expiresAt:       invoice.expiresAt,
      timeRemainingSeconds: timeRemaining,
      confirmedAt:     invoice.confirmedAt || null,
      txHash:          invoice.txHash || null,
      qrData: `tron:${invoice.walletAddress}?amount=${invoice.uniqueAmount}&token=USDT`,
      createdAt:       invoice.createdAt,
    },
  });
}

// ─── GET /api/v1/pay/:invoiceId/status ──────────────────────────────────────
// Ultra-lightweight polling endpoint — absolute minimum fields for status page

async function getPublicPayStatus(req, res) {
  const { invoiceId } = req.params;

  if (!invoiceId || !(/^inv_[a-zA-Z0-9]{12,32}$/.test(invoiceId))) {
    throw AppError.notFound('Invoice not found');
  }

  const invoice = await Invoice.findOne({ invoiceId })
    .select('invoiceId status confirmedAt txHash expiresAt uniqueAmount walletAddress')
    .lean();

  if (!invoice) throw AppError.notFound('Invoice not found');

  setCacheHeaders(res, invoice.status);

  const isTerminal = TERMINAL_STATUSES.has(invoice.status);
  const timeRemaining = !isTerminal && invoice.expiresAt
    ? Math.max(0, Math.floor((new Date(invoice.expiresAt) - Date.now()) / 1000))
    : 0;

  res.json({
    success: true,
    data: {
      invoiceId:            invoice.invoiceId,
      status:               invoice.status,
      isTerminal,
      timeRemainingSeconds: timeRemaining,
      confirmedAt:          invoice.confirmedAt || null,
      txHash:               invoice.txHash || null,
      // Include address/amount so polling client can keep showing them
      amountUsdt:           invoice.uniqueAmount,
      walletAddress:        invoice.walletAddress,
    },
  });
}

// ─── GET /api/v1/pay/:invoiceId/qr ──────────────────────────────────────────

async function getQrData(req, res) {
  const { invoiceId } = req.params;

  if (!invoiceId || !(/^inv_[a-zA-Z0-9]{12,32}$/.test(invoiceId))) {
    throw AppError.notFound('Invoice not found');
  }

  const invoice = await Invoice.findOne({ invoiceId })
    .select('invoiceId status uniqueAmount walletAddress currency network expiresAt')
    .lean();

  if (!invoice) throw AppError.notFound('Invoice not found');

  // QR data for wallet apps
  const qrData = `tron:${invoice.walletAddress}?amount=${invoice.uniqueAmount}&token=USDT`;

  // BIP-21 / TIP-712 style QR for Tron
  const deepLinkData = {
    address:  invoice.walletAddress,
    amount:   invoice.uniqueAmount,
    token:    'USDT',
    network:  'tron',
    qr:       qrData,
    isActive: !TERMINAL_STATUSES.has(invoice.status),
    expiresAt: invoice.expiresAt,
  };

  res.set('Cache-Control', 'no-store');
  res.json({ success: true, data: deepLinkData });
}

module.exports = {
  getPublicInvoice:    asyncHandler(getPublicInvoice),
  getPublicPayStatus:  asyncHandler(getPublicPayStatus),
  getQrData:           asyncHandler(getQrData),
};
