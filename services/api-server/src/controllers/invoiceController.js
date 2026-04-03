'use strict';

/**
 * @module controllers/invoiceController
 *
 * Invoice Controller — Merchant-facing payment creation.
 *
 * MERCHANT API (HMAC-signed requests):
 *   POST /api/v1/payments      — Create payment invoice
 *   GET  /api/v1/payments/:id  — Get payment status
 *   GET  /api/v1/payments      — List payments (paginated)
 *
 * SECURITY:
 *   - All routes validated by merchantApiAuth middleware (HMAC-SHA256 signature)
 *   - Nonce + timestamp === replay attack prevention
 *   - Merchant can only see their own invoices (merchantId enforced from JWT)
 *   - idempotencyKey prevents duplicate invoice creation
 */

const { schemas, validate } = require('@xcg/common');
const { config }             = require('../config');
const InvoiceService         = require('../services/invoiceService');
const WalletService          = require('../services/walletService');
const { Merchant }           = require('@xcg/database');
const logger                 = require('@xcg/logger').createLogger('invoice-ctrl');

// Shared lazy-init service singleton
let _invoiceService = null;

function getInvoiceService() {
  if (!_invoiceService) {
    const walletService = new WalletService({
      masterKey: config.encryption.masterKey,
      logger,
    });
    _invoiceService = new InvoiceService({
      config:        config.invoice,
      walletService,
      logger,
    });
  }
  return _invoiceService;
}

// ─── POST /api/v1/payments ───────────────────────────────────────────────────

async function createInvoice(req, res) {
  const data     = validate(schemas.invoice.create, req.body);
  const merchant = req.merchant; // Set by merchantApiAuth middleware

  const invoice = await getInvoiceService().createInvoice(data, merchant);

  res.status(201).json({
    success: true,
    data: {
      invoice: {
        invoiceId:     invoice.invoiceId,
        status:        invoice.status,
        amount:        invoice.baseAmount,
        uniqueAmount:  invoice.uniqueAmount,
        currency:      invoice.currency,
        network:       invoice.network,
        walletAddress: invoice.walletAddress,
        expiresAt:     invoice.expiresAt,
        paymentUrl:    `${process.env.PAYMENT_PAGE_URL || ''}/pay/${invoice.invoiceId}`,
      },
    },
  });
}

// ─── GET /api/v1/payments/:id ────────────────────────────────────────────────

async function getInvoice(req, res) {
  const { id } = req.params;
  const merchant = req.merchant;

  const invoice = await getInvoiceService().getInvoice(id, merchant._id);

  res.json({
    success: true,
    data: {
      invoice: {
        invoiceId:     invoice.invoiceId,
        status:        invoice.status,
        amount:        invoice.baseAmount,
        uniqueAmount:  invoice.uniqueAmount,
        currency:      invoice.currency,
        walletAddress: invoice.walletAddress,
        expiresAt:     invoice.expiresAt,
        confirmedAt:   invoice.confirmedAt,
        txHash:        invoice.txHash,
        netAmount:     invoice.netAmount,
        feeAmount:     invoice.feeAmount,
      },
    },
  });
}

// ─── GET /api/v1/payments ────────────────────────────────────────────────────

async function listInvoices(req, res) {
  const query    = validate(schemas.pagination, req.query);
  const merchant = req.merchant;

  const result = await getInvoiceService().listInvoices(merchant._id, {
    page:      query.page,
    limit:     query.limit,
    status:    req.query.status,
    sortBy:    query.sortBy,
    sortOrder: query.sortOrder,
  });

  res.json({ success: true, data: result });
}

module.exports = { createInvoice, getInvoice, listInvoices };
