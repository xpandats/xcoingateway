'use strict';

/**
 * @module controllers/merchantPortalController
 *
 * Merchant Portal — Self-service API for merchants authenticated via JWT.
 * All endpoints are scoped to the authenticated merchant's own data only.
 *
 * Security:
 *   - JWT authentication (authenticate middleware)
 *   - Role check: authorize('merchant')
 *   - All DB queries include merchantId filter (no cross-merchant data leakage)
 *   - Critical mutations (rotate webhook secret, revoke API key) are audit logged
 *
 * Routes (mounted at /api/v1/merchant):
 *   Profile:
 *     GET  /profile              — Get own merchant profile
 *     PUT  /profile              — Update business info, withdrawal address
 *   API Keys:
 *     GET  /api-keys             — List own API keys (secrets never returned)
 *     POST /api-keys             — Create new API key (secret returned ONCE)
 *     DELETE /api-keys/:keyId    — Revoke API key
 *   Webhook:
 *     GET  /webhook              — Get webhook config
 *     PUT  /webhook              — Update webhook URL + events
 *     POST /webhook/test         — Send test event
 *     POST /webhook/secret-rotate — Rotate signing secret
 *     GET  /webhook/deliveries   — Delivery history
 *   Dashboard & Data:
 *     GET  /dashboard            — Revenue KPIs
 *     GET  /transactions         — Own transaction history
 *     GET  /ledger               — Double-entry ledger entries
 *   Disputes:
 *     GET  /disputes             — Own disputes
 *     GET  /disputes/:id         — Dispute details
 *     POST /disputes             — Open dispute on a transaction
 *     POST /disputes/:id/respond — Submit evidence/response
 */

const Joi      = require('joi');
const crypto   = require('crypto');
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const { validate, AppError, ErrorCodes } = require('@xcg/common');
const { encrypt, decrypt, generateApiKey, generateApiSecret, generateWebhookSecret } = require('@xcg/crypto');
const {
  Merchant, Invoice, Transaction, LedgerEntry, Withdrawal,
  Dispute, WebhookDelivery, AuditLog,
} = require('@xcg/database');
const asyncHandler = require('../utils/asyncHandler');
const { WEBHOOK_EVENTS, DISPUTE_STATUS } = require('@xcg/common').constants;
const logger = require('@xcg/logger').createLogger('merchant-portal');

// ─── Validation Schemas ─────────────────────────────────────────────────────

const updateProfileSchema = Joi.object({
  businessName:             Joi.string().trim().min(2).max(200).optional(),
  email:                    Joi.string().email().optional(),
  withdrawalAddress:        Joi.string().pattern(/^T[1-9A-HJ-NP-Za-km-z]{33}$/).optional().allow(''),
  autoWithdrawal:           Joi.boolean().optional(),
  autoWithdrawalThreshold:  Joi.number().min(10).max(100000).optional(),
  ipWhitelistEnabled:       Joi.boolean().optional(),
  ipWhitelist:              Joi.array().items(Joi.string().ip()).max(20).optional(),
}).options({ stripUnknown: true });

const apiKeySchema = Joi.object({
  label:       Joi.string().trim().max(50).optional().allow('').default('API Key'),
  permissions: Joi.array().items(
    Joi.string().valid('payments:create', 'payments:read', 'withdrawals:create', 'withdrawals:read'),
  ).min(1).optional().default(['payments:create', 'payments:read']),
  expiresAt:   Joi.date().iso().min('now').optional().allow(null),
}).options({ stripUnknown: true });

const webhookUpdateSchema = Joi.object({
  webhookUrl:    Joi.string().uri({ scheme: ['https'] }).max(500).optional(),
  webhookEvents: Joi.array().items(Joi.string().valid(...Object.values(WEBHOOK_EVENTS || {
    PAYMENT_CREATED:      'payment.created',
    PAYMENT_DETECTED:     'payment.detected',
    PAYMENT_CONFIRMED:    'payment.confirmed',
    PAYMENT_EXPIRED:      'payment.expired',
    PAYMENT_FAILED:       'payment.failed',
    WITHDRAWAL_COMPLETED: 'withdrawal.completed',
    WITHDRAWAL_FAILED:    'withdrawal.failed',
    DISPUTE_OPENED:       'dispute.opened',
    DISPUTE_RESOLVED:     'dispute.resolved',
  }))).optional(),
}).options({ stripUnknown: true });

const paginationSchema = Joi.object({
  page:    Joi.number().integer().min(1).default(1),
  limit:   Joi.number().integer().min(1).max(100).default(20),
  status:  Joi.string().optional(),
  from:    Joi.date().iso().optional(),
  to:      Joi.date().iso().optional(),
}).options({ stripUnknown: true });

const openDisputeSchema = Joi.object({
  invoiceId:   Joi.string().required(),
  reason:      Joi.string().min(10).max(1000).required(),
  evidence:    Joi.string().max(5000).optional().allow(''),
  attachments: Joi.array().items(Joi.string().uri()).max(5).optional(),
}).options({ stripUnknown: true });

const respondDisputeSchema = Joi.object({
  response:    Joi.string().min(10).max(5000).required(),
  attachments: Joi.array().items(Joi.string().uri()).max(5).optional(),
}).options({ stripUnknown: true });

// ─── Helper: get merchant by req.user ───────────────────────────────────────

async function getMerchantForUser(userId) {
  const merchant = await Merchant.findOne({ userId }).lean();
  if (!merchant) throw AppError.notFound('Merchant profile not found', ErrorCodes.MERCHANT_NOT_FOUND);
  return merchant;
}

// ─────────────────────────────────────────────────────────────────────────────
// PROFILE
// ─────────────────────────────────────────────────────────────────────────────

async function getProfile(req, res) {
  const merchant = await getMerchantForUser(req.user._id);

  // Build safe response (no apiSecrets, no webhookSecret)
  const safe = {
    merchantId:                merchant._id,
    businessName:              merchant.businessName,
    email:                     merchant.email,
    isActive:                  merchant.isActive,
    isApproved:                merchant.isApproved,
    approvalStatus:            merchant.approvalStatus,
    withdrawalAddress:         merchant.withdrawalAddress || null,
    withdrawalAddressVerified: merchant.withdrawalAddressVerified,
    autoWithdrawal:            merchant.autoWithdrawal,
    autoWithdrawalThreshold:   merchant.autoWithdrawalThreshold,
    feePercentage:             merchant.feePercentage,
    fixedFee:                  merchant.fixedFee,
    ipWhitelistEnabled:        merchant.ipWhitelistEnabled,
    ipWhitelist:               merchant.ipWhitelist,
    webhookUrl:                merchant.webhookUrl || null,
    webhookEvents:             merchant.webhookEvents,
    hasWebhookSecret:          !!(merchant.webhookSecret && merchant.webhookSecret.length > 0),
    stats:                     merchant.stats,
    apiKeyCount:               (merchant.apiKeys || []).filter((k) => k.isActive).length,
    createdAt:                 merchant.createdAt,
  };

  res.json({ success: true, data: { merchant: safe } });
}

async function updateProfile(req, res) {
  const data = validate(updateProfileSchema, req.body);
  const merchant = await Merchant.findOne({ userId: req.user._id });
  if (!merchant) throw AppError.notFound('Merchant profile not found');

  // Withdrawal address change resets verification (requires admin re-verification)
  if (data.withdrawalAddress !== undefined && data.withdrawalAddress !== merchant.withdrawalAddress) {
    data.withdrawalAddressVerified = false;
    logger.warn('MerchantPortal: withdrawal address changed — re-verification required', {
      merchantId: String(merchant._id),
      userId:     String(req.user._id),
      newAddress: data.withdrawalAddress,
    });
  }

  Object.assign(merchant, data);
  await merchant.save();

  await AuditLog.create({
    actor:      String(req.user._id),
    action:     'merchant.profile_updated',
    resource:   'merchant',
    resourceId: String(merchant._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { fields: Object.keys(data) },
  });

  res.json({ success: true, data: { message: 'Profile updated', fields: Object.keys(data) } });
}

// ─────────────────────────────────────────────────────────────────────────────
// API KEYS
// ─────────────────────────────────────────────────────────────────────────────

async function listApiKeys(req, res) {
  const merchant = await getMerchantForUser(req.user._id);

  const keys = (merchant.apiKeys || []).filter((k) => k.isActive).map((k) => ({
    keyId:       k.keyId,
    label:       k.label,
    permissions: k.permissions,
    isActive:    k.isActive,
    lastUsedAt:  k.lastUsedAt,
    expiresAt:   k.expiresAt,
    createdAt:   k.createdAt,
  }));

  res.json({ success: true, data: { apiKeys: keys, total: keys.length } });
}

async function createApiKey(req, res) {
  const data = validate(apiKeySchema, req.body);
  const merchant = await Merchant.findOne({ userId: req.user._id });
  if (!merchant) throw AppError.notFound('Merchant profile not found');

  // Limit: max 10 active API keys per merchant
  const activeKeys = (merchant.apiKeys || []).filter((k) => k.isActive);
  if (activeKeys.length >= 10) {
    throw AppError.conflict('Maximum 10 active API keys allowed. Revoke an existing key first.', ErrorCodes.MERCHANT_API_KEY_LIMIT);
  }

  const plainApiKey    = generateApiKey();
  const plainApiSecret = generateApiSecret();

  // Hash the key for lookup, encrypt the secret for storage
  const keyHash        = await require('bcrypt').hash(plainApiKey, 10);
  const encryptedSecret = encrypt(plainApiSecret);

  const newKey = {
    keyId:       `key_${uuidv4().replace(/-/g, '').slice(0, 16)}`,
    keyHash,
    apiSecret:   encryptedSecret,
    label:       data.label,
    permissions: data.permissions,
    isActive:    true,
    expiresAt:   data.expiresAt || null,
    createdAt:   new Date(),
  };

  merchant.apiKeys.push(newKey);
  await merchant.save();

  await AuditLog.create({
    actor:      String(req.user._id),
    action:     'merchant.apikey_created',
    resource:   'merchant',
    resourceId: String(merchant._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { keyId: newKey.keyId, label: newKey.label, permissions: newKey.permissions },
  });

  logger.info('MerchantPortal: API key created', {
    merchantId: String(merchant._id),
    keyId:      newKey.keyId,
  });

  res.status(201).json({
    success: true,
    data: {
      keyId:      newKey.keyId,
      apiKey:     plainApiKey,
      apiSecret:  plainApiSecret,
      label:      newKey.label,
      permissions:newKey.permissions,
      expiresAt:  newKey.expiresAt,
      message:    'IMPORTANT: Save your API Secret now. It will never be shown again.',
    },
  });
}

async function revokeApiKey(req, res) {
  const { keyId } = req.params;
  const merchant = await Merchant.findOne({ userId: req.user._id });
  if (!merchant) throw AppError.notFound('Merchant profile not found');

  const key = (merchant.apiKeys || []).find((k) => k.keyId === keyId);
  if (!key) throw AppError.notFound('API key not found', ErrorCodes.MERCHANT_API_KEY_NOT_FOUND);
  if (!key.isActive) throw AppError.conflict('API key is already revoked');

  key.isActive = false;
  await merchant.save();

  await AuditLog.create({
    actor:      String(req.user._id),
    action:     'merchant.apikey_revoked',
    resource:   'merchant',
    resourceId: String(merchant._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { keyId },
  });

  res.json({ success: true, message: 'API key revoked. All requests using this key will immediately return 401.' });
}

// ─────────────────────────────────────────────────────────────────────────────
// WEBHOOK
// ─────────────────────────────────────────────────────────────────────────────

async function getWebhookConfig(req, res) {
  const merchant = await getMerchantForUser(req.user._id);

  res.json({
    success: true,
    data: {
      webhookUrl:    merchant.webhookUrl || null,
      webhookEvents: merchant.webhookEvents || [],
      hasWebhookSecret: !!(merchant.webhookSecret && merchant.webhookSecret.length > 0),
    },
  });
}

async function updateWebhookConfig(req, res) {
  const data = validate(webhookUpdateSchema, req.body);
  if (!data.webhookUrl && !data.webhookEvents) {
    throw AppError.badRequest('Provide webhookUrl and/or webhookEvents to update');
  }

  // SSRF check on webhook URL
  if (data.webhookUrl) {
    const { validateOutboundUrl } = require('../middleware/ssrfProtection');
    await validateOutboundUrl(data.webhookUrl);
  }

  const merchant = await Merchant.findOne({ userId: req.user._id });
  if (!merchant) throw AppError.notFound('Merchant profile not found');

  if (data.webhookUrl !== undefined)    merchant.webhookUrl    = data.webhookUrl;
  if (data.webhookEvents !== undefined) merchant.webhookEvents = data.webhookEvents;
  await merchant.save();

  await AuditLog.create({
    actor:      String(req.user._id),
    action:     'merchant.webhook_updated',
    resource:   'merchant',
    resourceId: String(merchant._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { fields: Object.keys(data) },
  });

  res.json({ success: true, message: 'Webhook configuration updated' });
}

async function sendTestWebhook(req, res) {
  const { event = 'payment.confirmed' } = req.body;
  const merchant = await getMerchantForUser(req.user._id);

  if (!merchant.webhookUrl) {
    throw AppError.badRequest('No webhook URL configured. Set one in /merchant/webhook first.', ErrorCodes.MERCHANT_WEBHOOK_URL_REQUIRED);
  }

  // Build test payload (mirrors real event structure)
  const testPayload = {
    event,
    invoiceId:   `inv_test_${Date.now()}`,
    merchantId:  String(merchant._id),
    deliveredAt: new Date().toISOString(),
    test:        true,
    data: {
      invoiceId:    `inv_test_${Date.now()}`,
      amount:       100.000001,
      txHash:       'test_tx_' + crypto.randomBytes(8).toString('hex'),
      status:       'confirmed',
      confirmedAt:  new Date().toISOString(),
    },
  };

  const axios = require('axios');
  const timestamp = Math.floor(Date.now() / 1000);
  const bodyStr   = JSON.stringify(testPayload);

  let webhookSecret = '';
  if (merchant.webhookSecret) {
    try { webhookSecret = decrypt(merchant.webhookSecret); } catch { webhookSecret = ''; }
  }

  const sig = webhookSecret
    ? crypto.createHmac('sha256', webhookSecret).update(`${timestamp}.${bodyStr}`).digest('hex')
    : 'test_no_secret';

  try {
    const { validateOutboundUrl } = require('../middleware/ssrfProtection');
    await validateOutboundUrl(merchant.webhookUrl);

    const resp = await axios.post(merchant.webhookUrl, testPayload, {
      timeout: 10_000,
      headers: {
        'Content-Type': 'application/json',
        'X-XCG-Signature': `t=${timestamp},v1=${sig}`,
        'X-XCG-Event': event,
        'X-XCG-Delivery': uuidv4(),
      },
    });

    res.json({
      success: true,
      data: {
        statusCode: resp.status,
        message:    'Test webhook delivered successfully',
        event,
      },
    });
  } catch (err) {
    const statusCode = err.response?.status || null;
    throw AppError.badRequest(
      `Test webhook delivery failed: ${err.message}. HTTP ${statusCode || 'N/A'}`,
      ErrorCodes.WEBHOOK_TEST_FAILED,
    );
  }
}

async function rotateWebhookSecret(req, res) {
  const merchant = await Merchant.findOne({ userId: req.user._id });
  if (!merchant) throw AppError.notFound('Merchant profile not found');

  const plainSecret    = generateWebhookSecret();
  merchant.webhookSecret = encrypt(plainSecret);
  await merchant.save();

  await AuditLog.create({
    actor:      String(req.user._id),
    action:     'merchant.webhook_secret_rotated',
    resource:   'merchant',
    resourceId: String(merchant._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
  });

  res.json({
    success: true,
    data: {
      webhookSecret: plainSecret,
      message:       'IMPORTANT: Update your webhook receiver with this new secret immediately. The old secret is now invalid.',
    },
  });
}

async function listWebhookDeliveries(req, res) {
  const { page, limit, status } = validate(paginationSchema, req.query);
  const merchant = await getMerchantForUser(req.user._id);

  const filter = { merchantId: new mongoose.Types.ObjectId(String(merchant._id)) };
  if (status) filter.status = status;

  const [deliveries, total] = await Promise.all([
    WebhookDelivery.find(filter)
      .select('-payload -signature') // Don't expose full payload or raw HMAC
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(),
    WebhookDelivery.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data: { deliveries, pagination: { page, limit, total, pages: Math.ceil(total / limit) } },
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// DASHBOARD & DATA
// ─────────────────────────────────────────────────────────────────────────────

async function getMerchantDashboard(req, res) {
  const merchant = await getMerchantForUser(req.user._id);
  const merchantObjId = new mongoose.Types.ObjectId(String(merchant._id));

  const now    = new Date();
  const last24h = new Date(now - 86_400_000);
  const last7d  = new Date(now - 7 * 86_400_000);
  const last30d = new Date(now - 30 * 86_400_000);
  const startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate());

  const [
    volume24h, volume7d, volume30d,
    confirmed24h, pendingInvoices,
    balanceResult, pendingWithdrawals,
    fees30d, totalInvoices, successfulInvoices,
  ] = await Promise.all([
    // Volume
    Transaction.aggregate([
      { $match: { merchantId: merchantObjId, status: 'confirmed', createdAt: { $gte: last24h } } },
      { $group: { _id: null, total: { $sum: '$amount' } } },
    ]).then((r) => r[0]?.total || 0),
    Transaction.aggregate([
      { $match: { merchantId: merchantObjId, status: 'confirmed', createdAt: { $gte: last7d } } },
      { $group: { _id: null, total: { $sum: '$amount' } } },
    ]).then((r) => r[0]?.total || 0),
    Transaction.aggregate([
      { $match: { merchantId: merchantObjId, status: 'confirmed', createdAt: { $gte: last30d } } },
      { $group: { _id: null, total: { $sum: '$amount' } } },
    ]).then((r) => r[0]?.total || 0),

    // Invoice counts
    Invoice.countDocuments({ merchantId: merchantObjId, status: 'confirmed', confirmedAt: { $gte: last24h } }),
    Invoice.countDocuments({
      merchantId: merchantObjId,
      status: { $in: ['initiated', 'pending', 'hash_found', 'confirming'] },
      expiresAt: { $gt: now },
    }),

    // Ledger balance
    LedgerEntry.aggregate([
      { $match: { merchantId: merchantObjId, account: 'merchant_receivable' } },
      { $group: {
        _id: null,
        credits: { $sum: { $cond: [{ $eq: ['$type', 'credit'] }, '$amount', 0] } },
        debits:  { $sum: { $cond: [{ $eq: ['$type', 'debit'] },  '$amount', 0] } },
      }},
    ]).then((r) => r[0] || { credits: 0, debits: 0 }),

    // Pending withdrawal amount
    Withdrawal.aggregate([
      { $match: { merchantId: merchantObjId, status: { $in: ['requested', 'pending_approval', 'processing'] } } },
      { $group: { _id: null, total: { $sum: '$amount' } } },
    ]).then((r) => r[0]?.total || 0),

    // Fees last 30d
    LedgerEntry.aggregate([
      { $match: { merchantId: merchantObjId, account: 'platform_fee', type: 'credit', createdAt: { $gte: last30d } } },
      { $group: { _id: null, total: { $sum: '$amount' } } },
    ]).then((r) => r[0]?.total || 0),

    Invoice.countDocuments({ merchantId: merchantObjId }),
    Invoice.countDocuments({ merchantId: merchantObjId, status: { $in: ['confirmed', 'success'] } }),
  ]);

  const available  = Math.max(0, (balanceResult.credits || 0) - (balanceResult.debits || 0));
  const successRate = totalInvoices > 0 ? parseFloat(((successfulInvoices / totalInvoices) * 100).toFixed(2)) : 0;

  res.json({
    success: true,
    data: {
      kpis: {
        balanceAvailable:      parseFloat(available.toFixed(6)),
        balancePending:        parseFloat(pendingWithdrawals.toFixed(6)),
        volumeUsdt24h:         parseFloat(volume24h.toFixed(6)),
        volumeUsdt7d:          parseFloat(volume7d.toFixed(6)),
        volumeUsdt30d:         parseFloat(volume30d.toFixed(6)),
        confirmedPayments24h:  confirmed24h,
        pendingInvoices,
        successRate,
        totalInvoices,
        fees30d:               parseFloat(fees30d.toFixed(6)),
      },
      generatedAt: now.toISOString(),
    },
  });
}

async function getMerchantTransactions(req, res) {
  const { page, limit, status, from, to } = validate(paginationSchema, req.query);
  const merchant = await getMerchantForUser(req.user._id);

  const filter = { merchantId: new mongoose.Types.ObjectId(String(merchant._id)) };
  if (status) filter.status = status;
  if (from || to) {
    filter.createdAt = {};
    if (from) filter.createdAt.$gte = new Date(from);
    if (to)   filter.createdAt.$lte = new Date(to);
  }

  const [transactions, total] = await Promise.all([
    Transaction.find(filter)
      .select('-fromAddress -blockNumber -confirmations -__v') // Hide internal blockchain fields from merchant
      .populate('matchedInvoiceId', 'invoiceId baseAmount uniqueAmount status')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(),
    Transaction.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data: { transactions, pagination: { page, limit, total, pages: Math.ceil(total / limit) } },
  });
}

async function getMerchantLedger(req, res) {
  const { page, limit, from, to } = validate(paginationSchema, req.query);
  const merchant = await getMerchantForUser(req.user._id);

  const filter = { merchantId: new mongoose.Types.ObjectId(String(merchant._id)) };
  if (from || to) {
    filter.createdAt = {};
    if (from) filter.createdAt.$gte = new Date(from);
    if (to)   filter.createdAt.$lte = new Date(to);
  }

  const [entries, total] = await Promise.all([
    LedgerEntry.find(filter)
      .select('-counterpartEntryId -idempotencyKey -__v')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(),
    LedgerEntry.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data: { entries, pagination: { page, limit, total, pages: Math.ceil(total / limit) } },
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// DISPUTES
// ─────────────────────────────────────────────────────────────────────────────

async function listOwnDisputes(req, res) {
  const { page, limit, status } = validate(paginationSchema, req.query);
  const merchant = await getMerchantForUser(req.user._id);

  const filter = { merchantId: new mongoose.Types.ObjectId(String(merchant._id)) };
  if (status) filter.status = status;

  const [disputes, total] = await Promise.all([
    Dispute.find(filter)
      .select('-adminNotes -__v')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(),
    Dispute.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data: { disputes, pagination: { page, limit, total, pages: Math.ceil(total / limit) } },
  });
}

async function getOwnDispute(req, res) {
  const merchant = await getMerchantForUser(req.user._id);

  const dispute = await Dispute.findOne({
    _id:        req.params.id,
    merchantId: new mongoose.Types.ObjectId(String(merchant._id)),
  }).select('-adminNotes -__v').lean();

  if (!dispute) throw AppError.notFound('Dispute not found', ErrorCodes.DISPUTE_NOT_FOUND);

  res.json({ success: true, data: { dispute } });
}

async function openDispute(req, res) {
  const data = validate(openDisputeSchema, req.body);
  const merchant = await getMerchantForUser(req.user._id);

  // Find the invoice
  const invoice = await Invoice.findOne({
    invoiceId:  data.invoiceId,
    merchantId: new mongoose.Types.ObjectId(String(merchant._id)),
  }).lean();

  if (!invoice) throw AppError.notFound('Invoice not found');
  if (!['confirmed', 'success'].includes(invoice.status)) {
    throw AppError.conflict('Can only raise a dispute on a confirmed/successful invoice');
  }

  // Check for existing open dispute
  const existingDispute = await Dispute.findOne({
    invoiceId: invoice._id,
    status:    { $nin: ['resolved_refund', 'resolved_no_refund', 'closed'] },
  }).lean();
  if (existingDispute) {
    throw AppError.conflict('An active dispute already exists for this invoice');
  }

  const dispute = await Dispute.create({
    disputeId:  `dsp_${uuidv4().replace(/-/g, '').slice(0, 16)}`,
    merchantId: merchant._id,
    invoiceId:  invoice._id,
    status:     'open',
    reason:     data.reason,
    evidence:   data.evidence || '',
    openedBy:   req.user._id,
    openedAt:   new Date(),
    deadline:   new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7-day response deadline
  });

  await AuditLog.create({
    actor:      String(req.user._id),
    action:     'dispute.opened',
    resource:   'dispute',
    resourceId: String(dispute._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { invoiceId: data.invoiceId, reason: data.reason },
  });

  res.status(201).json({ success: true, data: { dispute } });
}

async function respondToDispute(req, res) {
  const data = validate(respondDisputeSchema, req.body);
  const merchant = await getMerchantForUser(req.user._id);

  const dispute = await Dispute.findOne({
    _id:        req.params.id,
    merchantId: new mongoose.Types.ObjectId(String(merchant._id)),
  });

  if (!dispute) throw AppError.notFound('Dispute not found');
  if (['resolved_refund', 'resolved_no_refund', 'closed'].includes(dispute.status)) {
    throw AppError.conflict('Dispute is already resolved', ErrorCodes.DISPUTE_ALREADY_RESOLVED);
  }
  if (dispute.deadline && new Date() > dispute.deadline) {
    throw AppError.conflict('Dispute response deadline has passed', ErrorCodes.DISPUTE_DEADLINE_PASSED);
  }

  dispute.merchantResponse    = data.response;
  dispute.merchantRespondedAt = new Date();
  dispute.status              = 'merchant_responded';
  await dispute.save();

  await AuditLog.create({
    actor:      String(req.user._id),
    action:     'dispute.merchant_responded',
    resource:   'dispute',
    resourceId: String(dispute._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
  });

  res.json({ success: true, data: { dispute } });
}

// ─── Exports ─────────────────────────────────────────────────────────────────

module.exports = {
  // Profile
  getProfile:            asyncHandler(getProfile),
  updateProfile:         asyncHandler(updateProfile),
  // API Keys
  listApiKeys:           asyncHandler(listApiKeys),
  createApiKey:          asyncHandler(createApiKey),
  revokeApiKey:          asyncHandler(revokeApiKey),
  // Webhook
  getWebhookConfig:      asyncHandler(getWebhookConfig),
  updateWebhookConfig:   asyncHandler(updateWebhookConfig),
  sendTestWebhook:       asyncHandler(sendTestWebhook),
  rotateWebhookSecret:   asyncHandler(rotateWebhookSecret),
  listWebhookDeliveries: asyncHandler(listWebhookDeliveries),
  // Dashboard & Data
  getMerchantDashboard:  asyncHandler(getMerchantDashboard),
  getMerchantTransactions: asyncHandler(getMerchantTransactions),
  getMerchantLedger:     asyncHandler(getMerchantLedger),
  // Disputes
  listOwnDisputes:       asyncHandler(listOwnDisputes),
  getOwnDispute:         asyncHandler(getOwnDispute),
  openDispute:           asyncHandler(openDispute),
  respondToDispute:      asyncHandler(respondToDispute),
};
