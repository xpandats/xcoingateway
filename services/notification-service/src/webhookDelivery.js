'use strict';

/**
 * @module notification-service/webhookDelivery
 *
 * Webhook Delivery Engine — HMAC-signed payloads with 7-step retry.
 *
 * RETRY POLICY (per Description.txt):
 *   Attempt 1: Immediate
 *   Attempt 2: +30 seconds
 *   Attempt 3: +5 minutes
 *   Attempt 4: +30 minutes
 *   Attempt 5: +2 hours
 *   Attempt 6: +6 hours
 *   Attempt 7: FAILED → dead letter
 *
 * SECURITY:
 *   - Every payload signed with merchant's webhook secret (HMAC-SHA256)
 *   - Timestamp included in signature — prevents replay attacks
 *   - Merchant must return HTTP 200 within 10s
 *   - Delivery URL validated (SSRF protection — no private IPs)
 *   - Delivery history logged (WebhookDelivery model)
 */

const crypto  = require('crypto');
const axios   = require('axios');
const { WebhookDelivery, Merchant } = require('@xcg/database');
// validateOutboundUrl is in the ssrfProtection middleware (server-side, DNS-resolving SSRF check)
const { validateOutboundUrl } = require('../../middleware/ssrfProtection');

const DELIVERY_TIMEOUT_MS = 10_000; // 10 seconds

// Retry delays in milliseconds
const RETRY_DELAYS = [
  0,           // Attempt 1: immediate
  30_000,      // Attempt 2: 30s
  300_000,     // Attempt 3: 5min
  1_800_000,   // Attempt 4: 30min
  7_200_000,   // Attempt 5: 2hr
  21_600_000,  // Attempt 6: 6hr
];
const MAX_ATTEMPTS = RETRY_DELAYS.length + 1; // 7th = final failure

class WebhookDeliveryEngine {
  constructor({ logger }) {
    this.logger = logger;
  }

  /**
   * Deliver a webhook event to a merchant's callback URL.
   * Called by queue consumer — idempotent.
   *
   * @param {object} data           - { event, invoiceId, merchantId, txHash, amount, ... }
   * @param {string} idempotencyKey - Delivery idempotency key
   */
  async deliver(data, idempotencyKey) {
    const { event, merchantId, invoiceId } = data;

    // Load merchant's webhook config
    const merchant = await Merchant.findById(merchantId)
      .select('webhookUrl webhookSecret businessName isActive')
      .lean();

    if (!merchant?.webhookUrl) {
      this.logger.debug('WebhookDelivery: no webhook URL set for merchant', { merchantId });
      return;
    }
    if (!merchant.isActive) return;

    // SSRF protection — validate the URL before making any outbound request
    try {
      validateOutboundUrl(merchant.webhookUrl);
    } catch (err) {
      this.logger.error('WebhookDelivery: SSRF check failed on merchant webhook URL', {
        merchantId, error: err.message,
      });
      return; // Block silently — admin should audit this merchant
    }

    // Build payload
    const payload = {
      event,
      invoiceId:  invoiceId || null,
      merchantId: String(merchantId),
      data:       this._buildEventData(event, data),
      deliveredAt:new Date().toISOString(),
    };

    const payloadStr = JSON.stringify(payload);
    const timestamp  = Math.floor(Date.now() / 1000);

    // HMAC-SHA256 signature: `timestamp.payloadStr`
    // Same pattern as Stripe — predictable, well-understood format
    const webhookSecret = merchant.webhookSecret || '';
    const signature = crypto
      .createHmac('sha256', webhookSecret)
      .update(`${timestamp}.${payloadStr}`)
      .digest('hex');

    // Attempt delivery
    let attempt = 1;
    let success = false;
    let lastError = '';
    let responseCode = null;

    while (attempt <= MAX_ATTEMPTS) {
      const startMs = Date.now();
      try {
        const resp = await axios.post(merchant.webhookUrl, payload, {
          timeout: DELIVERY_TIMEOUT_MS,
          headers: {
            'Content-Type':     'application/json',
            'X-XCG-Signature':  `t=${timestamp},v1=${signature}`,
            'X-XCG-Event':      event,
            'X-XCG-Delivery':   idempotencyKey,
          },
          validateStatus: (s) => s === 200, // Only accept 200 as success
        });

        responseCode = resp.status;
        success = true;
        this.logger.info('WebhookDelivery: delivered successfully', {
          merchantId, event, attempt, latencyMs: Date.now() - startMs,
        });
        break;

      } catch (err) {
        responseCode = err.response?.status || null;
        lastError    = err.message;
        this.logger.warn('WebhookDelivery: delivery attempt failed', {
          merchantId, event, attempt, error: err.message, responseCode,
        });

        if (attempt < MAX_ATTEMPTS) {
          await this._delay(RETRY_DELAYS[attempt] || 0);
        }
        attempt++;
      }
    }

    // Record delivery attempt in DB
    await WebhookDelivery.create({
      merchantId,
      invoiceId:   invoiceId || null,
      event,
      url:         merchant.webhookUrl,
      payload:     payloadStr,
      success,
      attempts:    attempt - 1,
      lastResponseCode: responseCode,
      lastError:   success ? null : lastError,
      deliveredAt: success ? new Date() : null,
    }).catch((err) => this.logger.error('WebhookDelivery: failed to save delivery record', { error: err.message }));

    if (!success) {
      this.logger.error('WebhookDelivery: all attempts exhausted — permanently failed', {
        merchantId, event, attempts: attempt - 1, url: merchant.webhookUrl,
      });
    }
  }

  _buildEventData(event, data) {
    // Only include safe, event-relevant fields in webhook payload
    switch (event) {
      case 'payment.confirmed':
      case 'payment.detected':
        return {
          invoiceId:   data.invoiceId,
          amount:      data.amount,
          txHash:      data.txHash,
          status:      data.status || 'confirmed',
          confirmedAt: data.confirmedAt || new Date().toISOString(),
        };
      case 'payment.expired':
        return {
          invoiceId: data.invoiceId,
          amount:    data.amount,
          expiredAt: data.expiredAt || new Date().toISOString(),
        };
      case 'withdrawal.completed':
        return {
          withdrawalId: data.withdrawalId,
          amount:       data.amount,
          toAddress:    data.toAddress,
          txHash:       data.txHash,
          completedAt:  data.completedAt || new Date().toISOString(),
        };
      default:
        return { raw: data };
    }
  }

  _delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

module.exports = WebhookDeliveryEngine;
