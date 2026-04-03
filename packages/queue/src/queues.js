'use strict';

/**
 * @module queues
 *
 * Central registry of all queue names used in XCoinGateway.
 *
 * ARCHITECTURE: All inter-service communication goes through Redis queues.
 * Services NEVER call each other via HTTP.
 *
 * Data flow:
 *   API Server ──→ [PAYMENT_CREATED] ──→ Blockchain Listener
 *   Blockchain Listener ──→ [TRANSACTION_DETECTED] ──→ Matching Engine
 *   Matching Engine ──→ [PAYMENT_CONFIRMED] ──→ Notification Service
 *   Matching Engine ──→ [WITHDRAWAL_ELIGIBLE] ──→ Withdrawal Processor
 *   Withdrawal Processor ──→ [SIGNING_REQUEST] ──→ Signing Service (Zone 3)
 *   Signing Service ──→ [SIGNING_COMPLETE] ──→ Withdrawal Processor
 *   Any Service ──→ [SYSTEM_ALERT] ──→ Notification Service (Telegram/Email)
 *   Notification Service ──→ [WEBHOOK_DELIVER] ──→ Webhook Worker
 */

const QUEUES = Object.freeze({
  PAYMENT_CREATED:      'xcg:payment:created',
  TRANSACTION_DETECTED: 'xcg:transaction:detected',
  PAYMENT_CONFIRMED:    'xcg:payment:confirmed',
  PAYMENT_FAILED:       'xcg:payment:failed',
  WITHDRAWAL_ELIGIBLE:  'xcg:withdrawal:eligible',
  SIGNING_REQUEST:      'xcg:signing:request',
  SIGNING_COMPLETE:     'xcg:signing:complete',
  WEBHOOK_DELIVER:      'xcg:webhook:deliver',
  SYSTEM_ALERT:         'xcg:system:alert',
  DEAD_LETTER:          'xcg:dead:letter',
});

module.exports = { QUEUES };
