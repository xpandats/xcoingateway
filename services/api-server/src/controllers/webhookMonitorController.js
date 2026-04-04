'use strict';

/**
 * @module controllers/webhookMonitorController
 *
 * Admin Webhook Delivery Monitoring.
 *
 * Provides admin visibility and control over webhook delivery attempts.
 *
 * Routes (mounted at /admin/webhooks):
 *   GET  /deliveries           — All delivery attempts (paginated, filterable)
 *   GET  /deliveries/failed    — Permanently failed deliveries
 *   GET  /deliveries/:id       — Specific delivery detail
 *   POST /deliveries/:id/retry — Force-retry a failed delivery (TOTP)
 */

const Joi = require('joi');
const { validate, AppError, ErrorCodes } = require('@xcg/common');
const { WebhookDelivery, Merchant, AuditLog } = require('@xcg/database');
const asyncHandler = require('../utils/asyncHandler');
const { WEBHOOK_DELIVERY_STATUS } = require('@xcg/common').constants;
const logger = require('@xcg/logger').createLogger('webhook-monitor');

const paginationSchema = Joi.object({
  page:       Joi.number().integer().min(1).default(1),
  limit:      Joi.number().integer().min(1).max(100).default(20),
  status:     Joi.string().optional(),
  merchantId: Joi.string().hex().length(24).optional(),
  event:      Joi.string().optional(),
  from:       Joi.date().iso().optional(),
  to:         Joi.date().iso().optional(),
}).options({ stripUnknown: true });

// ─── List all deliveries ──────────────────────────────────────────────────────

async function listDeliveries(req, res) {
  const { page, limit, status, merchantId, event, from, to } = validate(paginationSchema, req.query);

  const filter = {};
  if (status)     filter.status     = status;
  if (merchantId) filter.merchantId = merchantId;
  if (event)      filter.event      = event;
  if (from || to) {
    filter.createdAt = {};
    if (from) filter.createdAt.$gte = new Date(from);
    if (to)   filter.createdAt.$lte = new Date(to);
  }

  const [deliveries, total] = await Promise.all([
    WebhookDelivery.find(filter)
      .select('-payload') // Payload can be large — only load on individual detail requests
      .populate('merchantId', 'businessName email')
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

// ─── List failed deliveries ───────────────────────────────────────────────────

async function listFailedDeliveries(req, res) {
  const { page, limit, merchantId } = validate(paginationSchema, req.query);

  const filter = { status: WEBHOOK_DELIVERY_STATUS?.FAILED || 'failed' };
  if (merchantId) filter.merchantId = merchantId;

  const [deliveries, total] = await Promise.all([
    WebhookDelivery.find(filter)
      .populate('merchantId', 'businessName email')
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

// ─── Get delivery detail ──────────────────────────────────────────────────────

async function getDelivery(req, res) {
  const delivery = await WebhookDelivery.findById(req.params.id)
    .populate('merchantId', 'businessName email webhookUrl')
    .lean();

  if (!delivery) throw AppError.notFound('Webhook delivery not found', ErrorCodes.WEBHOOK_DELIVERY_NOT_FOUND);

  res.json({ success: true, data: { delivery } });
}

// ─── Retry delivery ───────────────────────────────────────────────────────────

async function retryDelivery(req, res) {
  const delivery = await WebhookDelivery.findById(req.params.id);
  if (!delivery) throw AppError.notFound('Webhook delivery not found', ErrorCodes.WEBHOOK_DELIVERY_NOT_FOUND);

  // Only retry deliveries that have failed or are in error state
  const retryableStatuses = ['failed', 'error'];
  if (!retryableStatuses.includes(delivery.status)) {
    throw AppError.conflict(
      `Cannot retry a delivery in '${delivery.status}' status. Only failed/error deliveries can be retried.`,
      ErrorCodes.WEBHOOK_RETRY_NOT_ALLOWED,
    );
  }

  // Reset for retry (notification service will pick it up)
  delivery.status       = 'pending';
  delivery.nextRetryAt  = new Date(); // Immediate retry
  delivery.attempts     = Math.max(0, delivery.attempts - 1); // Give one more attempt
  await delivery.save();

  await AuditLog.create({
    actor:      String(req.user._id),
    action:     'webhook.delivery_retried',
    resource:   'webhook_delivery',
    resourceId: String(delivery._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { merchantId: String(delivery.merchantId), event: delivery.event },
  });

  logger.info('WebhookMonitor: admin forced retry', {
    deliveryId: String(delivery._id),
    adminId:    String(req.user._id),
  });

  res.json({
    success: true,
    message: 'Delivery queued for immediate retry. The notification service will attempt delivery within seconds.',
  });
}

module.exports = {
  listDeliveries:       asyncHandler(listDeliveries),
  listFailedDeliveries: asyncHandler(listFailedDeliveries),
  getDelivery:          asyncHandler(getDelivery),
  retryDelivery:        asyncHandler(retryDelivery),
};
