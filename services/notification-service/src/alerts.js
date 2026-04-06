'use strict';

/**
 * @module notification-service/alerts
 *
 * System Alert Delivery — Telegram Bot (zero-dependency, direct HTTP).
 *
 * Uses Telegram Bot HTTP API directly via axios — no third-party SDK.
 * SDK was removed due to transitive vulnerable dependencies (tough-cookie).
 *
 * Every alert is persisted to NotificationRecord for compliance audit.
 */

const crypto = require('crypto');
const axios = require('axios');
const { NotificationRecord } = require('@xcg/database');

const TELEGRAM_API_BASE   = 'https://api.telegram.org';
const TELEGRAM_TIMEOUT_MS = 8_000;

// Alert type → emoji mapping for quick visual scanning
const ALERT_EMOJI = {
  // Blockchain listener
  stale_block:                        '🔴',
  blockchain_circuit_open:            '🚨',
  stuck_transactions_recovery:        '🟡',

  // Matching engine
  late_payment:                       '🟡',
  underpayment:                       '🟡',
  overpayment:                        '🟡',
  duplicate_payment:                  '🚨',

  // Withdrawal engine
  no_hot_wallet:                      '🔴',
  withdrawal_requires_approval:       '🟠',
  daily_cap_reached:                  '🟠',
  withdrawal_to_own_wallet:           '🚨',
  withdrawal_over_per_tx_limit:       '🟠',
  withdrawal_blocked_active_dispute:  '🟡',
  withdrawal_confirmation_timeout:    '🔴',
  signing_complete_update_failed:     '🚨',
  stuck_signing_recovery_broadcast:   '🟠',
  stuck_signing_recovery_reset:       '🚨',
  insufficient_energy:                '⚡',
  low_tron_energy:                    '⚡',

  // Reconciliation service
  reconciliation_mismatch:            '🚨',

  // Auth / security
  account_locked_brute_force:         '🔐',
  totp_brute_force:                   '🔐',

  // DLQ monitor (all services)
  dead_letter_queue_has_messages:     '🔴',

  // Circuit breakers
  circuit_open:                       '🚨',
  circuit_close:                      '🟢',

  // System
  system_error:                       '❌',
  default:                            'ℹ️',
};

// Map alert type to severity
function _getSeverity(type) {
  const critical = new Set(['blockchain_circuit_open', 'duplicate_payment', 'no_hot_wallet',
    'reconciliation_mismatch', 'signing_complete_update_failed', 'circuit_open', 'system_error',
    'withdrawal_to_own_wallet', 'stuck_signing_recovery_reset', 'stale_block']);
  const warning = new Set(['late_payment', 'underpayment', 'overpayment', 'daily_cap_reached',
    'withdrawal_requires_approval', 'withdrawal_confirmation_timeout', 'dead_letter_queue_has_messages',
    'account_locked_brute_force', 'totp_brute_force', 'insufficient_energy']);
  if (critical.has(type)) return 'critical';
  if (warning.has(type)) return 'warning';
  return 'info';
}


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

    const notificationId = `ntf_${crypto.randomBytes(12).toString('hex')}`;
    const severity = _getSeverity(type);
    let deliveryStatus = 'skipped';
    let deliveryMs = null;
    let telegramMsgId = null;
    let lastError = null;

    if (this.botToken && this.chatId) {
      const start = Date.now();
      try {
        telegramMsgId = await this._sendTelegram(type, service, message, data);
        deliveryStatus = 'sent';
        deliveryMs = Date.now() - start;
      } catch (err) {
        deliveryStatus = 'failed';
        lastError = err.message;
        deliveryMs = Date.now() - start;
      }
    } else {
      this.logger.warn('AlertService: Telegram not configured — alert logged only', { type, service });
    }

    // Persist notification record (non-blocking)
    NotificationRecord.create({
      notificationId,
      channel:       'telegram',
      severity,
      subject:       `[${type}] System Alert`,
      message:       message || `Alert type: ${type}`,
      category:      type || 'system',
      status:        deliveryStatus,
      sentAt:        deliveryStatus === 'sent' ? new Date() : null,
      deliveryMs,
      lastError,
      telegramChatId: this.chatId || null,
      telegramMsgId,
      serviceOrigin:  service || 'unknown',
      resourceType:   data.resourceType || null,
      resourceId:     data.resourceId || data.invoiceId || data.withdrawalId || null,
      dedupeKey:      `${type}:${service}:${Math.floor(Date.now() / 60000)}`, // 1-min window
    }).catch((e) => this.logger.debug('AlertService: NotificationRecord write failed', { error: e.message }));
  }

  async _sendTelegram(type, service, message, data) {
    const emoji = ALERT_EMOJI[type] || ALERT_EMOJI.default;
    const env   = process.env.NODE_ENV || 'development';
    const ts    = new Date().toISOString();

    const text = [
      `${emoji} *XCG ALERT* \`${env.toUpperCase()}\``,
      ``,
      `*Type:* \`${type}\``,
      `*Service:* \`${service || 'unknown'}\``,
      `*Time:* ${ts}`,
      message ? `*Message:* ${message}` : null,
      data.txHash      ? `*TxHash:* \`${data.txHash}\``         : null,
      data.merchantId  ? `*Merchant:* \`${data.merchantId}\``   : null,
      data.amount      ? `*Amount:* ${data.amount} USDT`        : null,
      data.invoiceId   ? `*Invoice:* \`${data.invoiceId}\``     : null,
    ].filter(Boolean).join('\n');

    const result = await axios.post(
      `${TELEGRAM_API_BASE}/bot${this.botToken}/sendMessage`,
      { chat_id: this.chatId, text, parse_mode: 'Markdown' },
      { timeout: TELEGRAM_TIMEOUT_MS },
    );
    this.logger.debug('AlertService: Telegram message sent', { type });
    return result.data?.result?.message_id ? String(result.data.result.message_id) : null;
  }
}

module.exports = AlertService;

