'use strict';

/**
 * @module notification-service/alerts
 *
 * System Alert Delivery — Telegram Bot (zero-dependency, direct HTTP).
 *
 * Uses Telegram Bot HTTP API directly via axios — no third-party SDK.
 * SDK was removed due to transitive vulnerable dependencies (tough-cookie).
 *
 * ALERT TRIGGERS (from various services):
 *   - stale_block             (Blockchain Listener)
 *   - blockchain_circuit_open (Blockchain Listener)
 *   - late_payment            (Matching Engine)
 *   - reconciliation_mismatch (Reconciliation Service)
 *   - no_hot_wallet           (Withdrawal Engine)
 *   - withdrawal_requires_approval (Withdrawal Engine)
 *   - daily_cap_reached       (Withdrawal Engine)
 *   - system_error            (Any service)
 */

const axios = require('axios');

const TELEGRAM_API_BASE   = 'https://api.telegram.org';
const TELEGRAM_TIMEOUT_MS = 8_000;

// Alert type → emoji mapping for quick visual scanning
const ALERT_EMOJI = {
  stale_block:                  '🔴',
  blockchain_circuit_open:      '🚨',
  late_payment:                 '🟡',
  reconciliation_mismatch:      '🚨',
  no_hot_wallet:                '🔴',
  withdrawal_requires_approval: '🟠',
  daily_cap_reached:            '🟠',
  withdrawal_to_own_wallet:     '🚨',
  withdrawal_over_per_tx_limit: '🟠',
  system_error:                 '❌',
  default:                      'ℹ️',
};

class AlertService {
  /**
   * @param {object} opts
   * @param {string} opts.botToken  - Telegram Bot token (from ENV)
   * @param {string} opts.chatId    - Telegram chat ID for alerts
   * @param {object} opts.logger
   */
  constructor({ botToken, chatId, logger }) {
    this.botToken = botToken;
    this.chatId   = chatId;
    this.logger   = logger;
  }

  /**
   * Process an alert event from the SYSTEM_ALERT queue.
   * @param {object} data - Alert payload { type, service, message, ... }
   */
  async handle(data) {
    const { type, service, message } = data;
    this.logger.warn('AlertService: system alert received', { type, service });

    if (this.botToken && this.chatId) {
      await this._sendTelegram(type, service, message, data);
    } else {
      this.logger.warn('AlertService: Telegram not configured — alert logged only', { type, service });
    }
  }

  async _sendTelegram(type, service, message, data) {
    const emoji = ALERT_EMOJI[type] || ALERT_EMOJI.default;
    const env   = process.env.NODE_ENV || 'development';
    const ts    = new Date().toISOString();

    // Build clean, readable alert message
    const text = [
      `${emoji} *XCG ALERT* \`${env.toUpperCase()}\``,
      ``,
      `*Type:* \`${type}\``,
      `*Service:* \`${service || 'unknown'}\``,
      `*Time:* ${ts}`,
      message ? `*Message:* ${message}` : null,
      // Include relevant fields (not sensitive ones)
      data.txHash      ? `*TxHash:* \`${data.txHash}\``         : null,
      data.merchantId  ? `*Merchant:* \`${data.merchantId}\``   : null,
      data.amount      ? `*Amount:* ${data.amount} USDT`        : null,
      data.invoiceId   ? `*Invoice:* \`${data.invoiceId}\``     : null,
    ].filter(Boolean).join('\n');

    try {
      await axios.post(
        `${TELEGRAM_API_BASE}/bot${this.botToken}/sendMessage`,
        { chat_id: this.chatId, text, parse_mode: 'Markdown' },
        { timeout: TELEGRAM_TIMEOUT_MS },
      );
      this.logger.debug('AlertService: Telegram message sent', { type });
    } catch (err) {
      // Never let alert delivery failure crash the service
      this.logger.error('AlertService: Telegram delivery failed', {
        type, error: err.message,
        // Don't log botToken
      });
    }
  }
}

module.exports = AlertService;
