'use strict';

/**
 * @module matching-engine/server
 * Entry point for the Matching Engine service.
 * Runs both the matching engine consumer AND the invoice expiry scanner.
 */

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env.local') });

const { config, validateConfig }             = require('../../api-server/src/config');
const { connectDB }                           = require('@xcg/database');
const { createLogger }                        = require('@xcg/logger');
const { createConsumer, createPublisher, QUEUES } = require('@xcg/queue');
const { startHealthServer }                   = require('@xcg/common/src/healthServer');
const IORedis                                 = require('ioredis');
const mongoose                                = require('mongoose');
const MatchingEngine                          = require('./engine');
const InvoiceExpiryScanner                    = require('./invoiceExpiry');

const logger = createLogger('matching-engine');

async function main() {
  logger.info('MatchingEngine: starting up');

  try { validateConfig(); } catch (err) {
    logger.error('MatchingEngine: config validation failed', { error: err.message });
    process.exit(1);
  }

  await connectDB(config.db.uri, logger);

  const redis = new IORedis(config.redis.url, { maxRetriesPerRequest: null });
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

  // Matching Engine
  const engine = new MatchingEngine({
    minConfirmations:   config.tron.confirmationsRequired,
    platformFeeRate:    config.invoice.platformFeeRate,
    confirmedPublisher,
    alertPublisher,
    withdrawalPublisher,
    logger,
  });

  // Invoice Expiry Scanner — P0 fix: runs alongside the engine
  const expiryScanner = new InvoiceExpiryScanner({
    expiredPublisher: paymentFailedPublisher,
    logger,
  });

  // Consumer: main transaction matching
  const { worker } = createConsumer(
    QUEUES.TRANSACTION_DETECTED,
    redisOpts,
    config.queue.signingSecret,
    logger,
    (data, idempotencyKey) => engine.handle(data, idempotencyKey),
    { concurrency: 5 },
  );

  // Start the expiry scanner background job
  expiryScanner.start();

  async function shutdown(signal) {
    logger.info(`MatchingEngine: ${signal} — shutting down`);
    expiryScanner.stop();
    await worker.close();
    await redis.quit();
    process.exit(0);
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));
  process.on('uncaughtException',  (err) => { logger.error('MatchingEngine: uncaught', { error: err.message }); process.exit(1); });
  process.on('unhandledRejection', (r)   => { logger.error('MatchingEngine: unhandled rejection', { reason: String(r) }); process.exit(1); });

  logger.info('MatchingEngine: running — waiting for transactions');
}

main().catch((err) => { console.error('MatchingEngine: fatal startup error', err.message); process.exit(1); });
