'use strict';

/**
 * @module matching-engine/server
 * Entry point for the Matching Engine service.
 * Runs the matching engine consumer, confirmation tracker, and invoice expiry scanner.
 *
 * PHASE 2 COMPLETE FLOW:
 *   1. MatchingEngine:         consumes TRANSACTION_DETECTED → sets HASH_FOUND + creates DETECTED Tx
 *   2. ConfirmationTracker:    polls DETECTED Txs every 10s → calls _confirmPayment() at 19 confirms
 *   3. InvoiceExpiryScanner:   fires payment.expired for PENDING invoices past expiresAt
 */

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env.local') });

const { config, validateConfig }             = require('../../api-server/src/config');
const { connectDB }                           = require('@xcg/database');
const { createLogger }                        = require('@xcg/logger');
const { createConsumer, createPublisher, createDLQMonitor, QUEUES } = require('@xcg/queue');
const { startHealthServer }                   = require('@xcg/common/src/healthServer');
const { TronAdapter }                         = require('@xcg/tron');
const { createRedisClient }                   = require('@xcg/common/src/redisFactory');
const { registerShutdown, runMain }           = require('@xcg/common/src/shutdown');
const mongoose                                = require('mongoose');


const MatchingEngine                          = require('./engine');
const ConfirmationTracker                     = require('./confirmationTracker');
const InvoiceExpiryScanner                    = require('./invoiceExpiry');

const logger = createLogger('matching-engine');

async function main() {
  logger.info('MatchingEngine: starting up');

  try { validateConfig(); } catch (err) {
    logger.error('MatchingEngine: config validation failed', { error: err.message });
    process.exit(1);
  }

  await connectDB(config.db.uri, logger);

  const redis = createRedisClient({ logger }); // Gap 5: Sentinel/Cluster-aware
  redis.on('error', (err) => logger.error('MatchingEngine: Redis error', { error: err.message }));


  // Health check server (internal only — port 3093)
  startHealthServer({ port: 3093, service: 'matching-engine', mongoose, redis, logger });

  const redisOpts = {
    host: new URL(config.redis.url).hostname,
    port: Number(new URL(config.redis.url).port) || 6379,
  };

  // Publishers
  const confirmedPublisher  = createPublisher(QUEUES.PAYMENT_CONFIRMED,  redisOpts, config.queue.signingSecret, logger);
  const alertPublisher      = createPublisher(QUEUES.SYSTEM_ALERT,        redisOpts, config.queue.signingSecret, logger);
  const withdrawalPublisher = createPublisher(QUEUES.WITHDRAWAL_ELIGIBLE, redisOpts, config.queue.signingSecret, logger);
  // PAYMENT_FAILED queue used by expiry scanner for payment.expired events
  const paymentFailedPublisher = createPublisher(QUEUES.PAYMENT_FAILED,  redisOpts, config.queue.signingSecret, logger);

  // TronAdapter — used by ConfirmationTracker to query latest block height
  const tronAdapter = new TronAdapter(
    { network: config.tron.network, apiKey: config.tron.apiKey },
    logger,
  );

  // Matching Engine (Phase 1: detection + validation)
  const engine = new MatchingEngine({
    minConfirmations:   config.tron.confirmationsRequired,
    platformFeeRate:    config.invoice.platformFeeRate,
    confirmedPublisher,
    alertPublisher,
    withdrawalPublisher,
    logger,
  });

  // Confirmation Tracker (Phase 2: polls DETECTED txs until 19 confirmations)
  const tracker = new ConfirmationTracker({
    adapter:          tronAdapter,
    engine,
    alertPublisher,
    minConfirmations: config.tron.confirmationsRequired,
    logger,
  });

  // Invoice Expiry Scanner — fires payment.expired webhooks
  const expiryScanner = new InvoiceExpiryScanner({
    expiredPublisher: paymentFailedPublisher,
    logger,
  });

  // Consumer: main transaction matching (Phase 1)
  const { worker } = createConsumer(
    QUEUES.TRANSACTION_DETECTED,
    redisOpts,
    config.queue.signingSecret,
    logger,
    (data, idempotencyKey) => engine.handle(data, idempotencyKey),
    { concurrency: 5 },
  );

  // Start background jobs
  await tracker.start();   // Runs stuck-tx recovery immediately + starts 10s poll loop
  expiryScanner.start();   // Runs expired invoice sweep every 60s

  // M3 FIX: DLQ monitor — alerts on any messages in dead letter queue
  const dlqMonitor = createDLQMonitor({
    redisOpts,
    secret:         config.queue.signingSecret,
    alertPublisher,
    serviceName:    'matching-engine',
    logger,
  });

  registerShutdown({
    logger,
    service: 'matching-engine',
    cleanup: async () => {
      tracker.stop();
      expiryScanner.stop();
      dlqMonitor.stop();
      await worker.close();
      await redis.quit();
    },
  });

  logger.info('MatchingEngine: fully running — Phase 1 (detection) + Phase 2 (confirmation) + Expiry Scanner');
}

runMain(main, { logger, service: 'matching-engine' });

