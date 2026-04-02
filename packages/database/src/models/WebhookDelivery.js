'use strict';

const mongoose = require('mongoose');
const { WEBHOOK_EVENTS, WEBHOOK_DELIVERY_STATUS } = require('@xcg/common').constants;

const webhookDeliverySchema = new mongoose.Schema({
  merchantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant', required: true, index: true },
  event: { type: String, enum: Object.values(WEBHOOK_EVENTS), required: true, index: true },
  url: { type: String, required: true },
  payload: { type: mongoose.Schema.Types.Mixed, required: true },
  signature: { type: String, required: true },

  status: {
    type: String,
    enum: Object.values(WEBHOOK_DELIVERY_STATUS),
    default: WEBHOOK_DELIVERY_STATUS.PENDING,
    index: true,
  },

  attempts: { type: Number, default: 0 },
  maxAttempts: { type: Number, default: 6 },
  nextRetryAt: { type: Date, default: null, index: true },
  lastAttemptAt: { type: Date, default: null },
  lastResponseCode: { type: Number, default: null },
  lastResponseBody: { type: String, default: null, maxlength: 1000 },
  lastError: { type: String, default: null },
  deliveredAt: { type: Date, default: null },
}, {
  timestamps: true,
  collection: 'webhook_deliveries',
});

webhookDeliverySchema.index({ status: 1, nextRetryAt: 1 });
webhookDeliverySchema.index({ merchantId: 1, createdAt: -1 });

module.exports = mongoose.model('WebhookDelivery', webhookDeliverySchema);
