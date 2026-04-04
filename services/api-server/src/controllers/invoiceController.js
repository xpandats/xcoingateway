'use strict';

/**
 * @module controllers/invoiceController — FIXED
 *
 * Merchant-facing payment invoice endpoints.
 * All routes use HMAC-signed merchant API auth.
 */

const Joi        = require('joi');
const { validate, AppError } = require('@xcg/common');
const { INVOICE_STATUS } = require('@xcg/common').constants;
const FraudEngine    = require('@xcg/common/src/fraudEngine');
const asyncHandler   = require('../utils/asyncHandler');
const InvoiceService = require('../services/invoiceService');
const WalletService  = require('../services/walletService');
const { config }     = require('../config');

const logger = require('@xcg/logger').createLogger('invoice-ctrl');

// Queue publisher for payment.created event (lazy-init — wired up by app.js)
let _paymentCreatedPublisher = null;
function setPaymentCreatedPublisher(publisher) { _paymentCreatedPublisher = publisher; }

// Lazy-init singletons
let _walletService, _invoiceService, _fraud;

function getServices() {
  if (!_walletService) _walletService = new WalletService({ logger });
  if (!_invoiceService) _invoiceService = new InvoiceService({ walletService: _walletService, logger });
  // FraudEngine uses alertPublisher — wired when publisher is available, else no alert
  if (!_fraud) _fraud = new FraudEngine({ alertPublisher: _paymentCreatedPublisher, logger });
  return _invoiceService;
}

// ─── Validation ──────────────────────────────────────────────────────────────

const createSchema = Joi.object({
  amount:         Joi.number().min(0.01).max(1000000).precision(6).required(),
  currency:       Joi.string().valid('USDT').default('USDT'),
  description:    Joi.string().trim().max(500).optional().allow(''),
  metadata:       Joi.object().max(10).optional(),
  callbackUrl:    Joi.string().uri({ scheme: ['https'] }).max(500).optional(),
  idempotencyKey: Joi.string().uuid().optional(),
}).options({ stripUnknown: true });

const listSchema = Joi.object({
  page:   Joi.number().integer().min(1).default(1),
  limit:  Joi.number().integer().min(1).max(100).default(20),
  status: Joi.string().valid(...Object.values(INVOICE_STATUS)).optional(),
}).options({ stripUnknown: true });

// ─── Handlers ────────────────────────────────────────────────────────────────

async function createInvoice(req, res) {
  const data = validate(createSchema, req.body);

  // SSRF: validate callbackUrl if provided
  if (data.callbackUrl) {
    const { validateOutboundUrl } = require('../middleware/ssrfProtection');
    await validateOutboundUrl(data.callbackUrl);
  }

  // FRAUD CHECK: velocity limits + amount cap before invoice is created
  // This prevents API abuse (merchants flooding invoice creation)
  getServices(); // Ensure _fraud is initialised
  const fraudResult = await _fraud.checkInvoiceCreation(
    req.merchant._id,
    { baseAmount: data.amount },
    { ipAddress: req.ip, userAgent: req.headers['user-agent'] },
  );
  if (fraudResult.blocked) {
    throw new AppError(429, fraudResult.reason, 'FRAUD_BLOCKED');
  }
  // Flagged = proceed but it's already logged + alerted by fraud engine

  const invoice = await getServices().createInvoice(data, req.merchant);

  // Fire payment.created webhook event (non-blocking — don't fail invoice creation)
  if (_paymentCreatedPublisher && invoice.callbackUrl) {
    _paymentCreatedPublisher.publish(
      {
        event:      'payment.created',
        invoiceId:  invoice._id || invoice.invoiceId,
        merchantId: String(req.merchant._id),
        amount:     String(invoice.baseAmount),
        uniqueAmount: String(invoice.uniqueAmount),
        currency:   invoice.currency,
        network:    invoice.network,
        walletAddress: invoice.walletAddress,
        expiresAt:  invoice.expiresAt,
        callbackUrl:invoice.callbackUrl,
        createdAt:  new Date().toISOString(),
      },
      `payment.created:${invoice.invoiceId || invoice._id}`,
    ).catch((err) => logger.warn('invoiceController: failed to publish payment.created', { error: err.message }));
  }

  res.status(201).json({
    success: true,
    data:    { invoice },
  });
}

async function getInvoice(req, res) {
  const invoice = await getServices().getInvoice(req.params.id, req.merchant._id);
  res.json({ success: true, data: { invoice } });
}

async function listInvoices(req, res) {
  const query  = validate(listSchema, req.query);
  const result = await getServices().listInvoices(req.merchant._id, query);
  res.json({ success: true, data: result });
}

// ─── Payment Status Endpoint (merchant polling) ───────────────────────────────

async function getPaymentStatus(req, res) {
  const invoice = await getServices().getInvoice(req.params.id, req.merchant._id);

  // Map to partner-friendly status
  const statusMap = {
    [INVOICE_STATUS.INITIATED]:  'created',
    [INVOICE_STATUS.PENDING]:    'awaiting_payment',
    [INVOICE_STATUS.HASH_FOUND]: 'processing',
    [INVOICE_STATUS.CONFIRMING]: 'confirming',
    [INVOICE_STATUS.CONFIRMED]:  'confirmed',
    [INVOICE_STATUS.SUCCESS]:    'completed',
    [INVOICE_STATUS.EXPIRED]:    'expired',
    [INVOICE_STATUS.FAILED]:     'failed',
    [INVOICE_STATUS.CANCELLED]:  'cancelled',
    [INVOICE_STATUS.UNDERPAID]:  'underpaid',
    [INVOICE_STATUS.OVERPAID]:   'overpaid',
  };

  res.json({
    success: true,
    data: {
      invoiceId:     invoice.invoiceId,
      status:        invoice.status,
      displayStatus: statusMap[invoice.status] || invoice.status,
      amount:        invoice.baseAmount,
      uniqueAmount:  invoice.uniqueAmount,
      currency:      invoice.currency,
      network:       invoice.network,
      walletAddress: invoice.walletAddress,
      expiresAt:     invoice.expiresAt,
      confirmedAt:   invoice.confirmedAt || null,
      txHash:        invoice.txHash || null,
      netAmount:     invoice.netAmount || null,
    },
  });
}

module.exports = {
  createInvoice:    asyncHandler(createInvoice),
  getInvoice:       asyncHandler(getInvoice),
  listInvoices:     asyncHandler(listInvoices),
  getPaymentStatus: asyncHandler(getPaymentStatus),
  setPaymentCreatedPublisher,
};
