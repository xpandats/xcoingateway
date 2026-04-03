'use strict';

/**
 * @module utils/webhookSigner
 *
 * WH-1: Outbound Webhook Signature Utility.
 *
 * WHY: When your server sends webhooks to merchants, the merchant must
 * verify the payload came from XCoinGateway (not an attacker who guessed
 * the webhook URL). Unsigned webhooks allow:
 *   - Replay attacks (attacker resends old webhook)
 *   - Forgery (attacker sends fake payment confirmation)
 *
 * IMPLEMENTATION:
 *   Sign payload with HMAC-SHA256 using merchant's webhookSecret.
 *   Merchant verifies the X-XCG-Signature header matches HMAC of body.
 *
 * SIGNATURE FORMAT:
 *   X-XCG-Signature: t=<timestamp>,v1=<hex_hmac>
 *
 *   Including timestamp prevents replay attacks (merchant rejects
 *   signatures where |now - t| > 300 seconds).
 *
 * WH-2: URL validation on EVERY delivery (not just on creation).
 *   validateOutboundUrl is called before every webhook HTTP request.
 *
 * MERCHANT VERIFICATION (document in API docs):
 *   const [tPart, vPart] = header.split(',');
 *   const t = tPart.split('=')[1];
 *   const v = vPart.split('=')[1];
 *   const expected = HMAC-SHA256(webhookSecret, `${t}.${JSON.stringify(body)}`);
 *   const isValid = timingSafeEqual(expected, v) && Math.abs(Date.now()/1000 - t) < 300;
 */

const crypto = require('crypto');
const https = require('https');
const { validateOutboundUrl } = require('../middleware/ssrfProtection');
const { createLogger } = require('@xcg/logger');
const { decrypt } = require('@xcg/crypto');

const logger = createLogger('webhook-signer');

const REPLAY_WINDOW_SECONDS = 300; // 5 minutes

/**
 * Generate a signed webhook signature header.
 *
 * @param {Buffer|string} webhookSecret - Plaintext webhook secret (decrypt before calling)
 * @param {object} payload - Webhook payload object
 * @returns {{ signature: string, timestamp: number, body: string }}
 */
function signWebhook(webhookSecret, payload) {
  const timestamp = Math.floor(Date.now() / 1000);
  const body = JSON.stringify(payload);
  const signingInput = `${timestamp}.${body}`;

  const signature = crypto
    .createHmac('sha256', webhookSecret)
    .update(signingInput, 'utf8')
    .digest('hex');

  return {
    signature: `t=${timestamp},v1=${signature}`,
    timestamp,
    body,
  };
}

/**
 * Verify an incoming webhook signature (for merchant testing tools).
 *
 * @param {string} webhookSecret - Plaintext secret
 * @param {string} rawBody - Raw request body string (NOT parsed JSON)
 * @param {string} signatureHeader - Value of X-XCG-Signature header
 * @returns {boolean} true if valid and within replay window
 */
function verifyWebhookSignature(webhookSecret, rawBody, signatureHeader) {
  try {
    const parts = Object.fromEntries(signatureHeader.split(',').map((p) => p.split('=')));
    const timestamp = parseInt(parts.t, 10);
    const receivedSig = parts.v1;

    if (!timestamp || !receivedSig) return false;

    // Replay protection: reject signatures older than 5 minutes
    const age = Math.abs(Math.floor(Date.now() / 1000) - timestamp);
    if (age > REPLAY_WINDOW_SECONDS) return false;

    const signingInput = `${timestamp}.${rawBody}`;
    const expected = crypto
      .createHmac('sha256', webhookSecret)
      .update(signingInput, 'utf8')
      .digest('hex');

    // Constant-time comparison to prevent timing attacks
    return crypto.timingSafeEqual(
      Buffer.from(expected, 'hex'),
      Buffer.from(receivedSig, 'hex'),
    );
  } catch {
    return false;
  }
}

/**
 * Deliver a signed webhook payload to a merchant URL.
 * WH-2: Validates URL immediately before delivery (not just at creation time).
 *
 * @param {string} encryptedWebhookSecret - AES-encrypted webhook secret from Merchant model
 * @param {string} webhookUrl - Target URL
 * @param {object} payload - Payload to deliver
 * @param {object} [options]
 * @param {number} [options.timeoutMs=10000] - Request timeout in ms
 * @returns {Promise<{ statusCode: number, success: boolean }>}
 */
async function deliverWebhook(encryptedWebhookSecret, webhookUrl, payload, options = {}) {
  const { timeoutMs = 10000 } = options;

  // WH-2: Validate URL on EVERY delivery attempt (DNS rebinding: URL may have changed)
  await validateOutboundUrl(webhookUrl);

  const plaintextSecret = decrypt(encryptedWebhookSecret);
  const { signature, body } = signWebhook(plaintextSecret, payload);

  return new Promise((resolve, reject) => {
    const url = new URL(webhookUrl);
    const postBody = body;

    const reqOptions = {
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postBody),
        'X-XCG-Signature': signature,
        'User-Agent': 'XCoinGateway-Webhook/1.0',
      },
      timeout: timeoutMs,
    };

    const req = https.request(reqOptions, (res) => {
      // Drain the response to free sockets
      res.resume();
      resolve({ statusCode: res.statusCode, success: res.statusCode >= 200 && res.statusCode < 300 });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Webhook delivery timeout after ${timeoutMs}ms`));
    });

    req.on('error', (err) => {
      logger.warn('Webhook delivery failed', { url: webhookUrl, error: err.message });
      reject(err);
    });

    req.write(postBody);
    req.end();
  });
}

module.exports = { signWebhook, verifyWebhookSignature, deliverWebhook };
