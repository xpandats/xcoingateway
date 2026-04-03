'use strict';

/**
 * @module matching-engine/server
 * Entry point for the Matching Engine service.
 */

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env.local') });

const { config, validateConfig }          = require('../../api-server/src/config');
const { connectDB }                        = require('@xcg/database');
const { createLogger }                     = require('@xcg/logger');
const { createConsumer, createPublisher, QUEUES } = require('@xcg/queue');
const IORedis                              = require('ioredis');
const MatchingEngine                       = require('./engine');

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

  const redisOpts = {
    host: new URL(config.redis.url).hostname,
    port: Number(new URL(config.redis.url).port) || 6379,
  };

  const confirmedPublisher  = createPublisher(QUEUES.PAYMENT_CONFIRMED,   redisOpts, config.queue.signingSecret, logger);
  const alertPublisher      = createPublisher(QUEUES.SYSTEM_ALERT,         redisOpts, config.queue.signingSecret, logger);
  const withdrawalPublisher = createPublisher(QUEUES.WITHDRAWAL_ELIGIBLE,  redisOpts, config.queue.signingSecret, logger);

  const engine = new MatchingEngine({
    minConfirmations:   config.tron.confirmationsRequired,
    platformFeeRate:    config.invoice.platformFeeRate,
    confirmedPublisher,
    alertPublisher,
    withdrawalPublisher,
    logger,
  });

  const { worker } = createConsumer(
    QUEUES.TRANSACTION_DETECTED,
    redisOpts,
    config.queue.signingSecret,
    logger,
    (data, idempotencyKey) => engine.handle(data, idempotencyKey),
    { concurrency: 5 },
  );

  async function shutdown(signal) {
    logger.info(`MatchingEngine: ${signal} — shutting down`);
    await worker.close();
    await redis.quit();
    process.exit(0);
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));
  process.on('uncaughtException', (err) => { logger.error('MatchingEngine: uncaught', { error: err.message }); process.exit(1); });
  process.on('unhandledRejection', (r)  => { logger.error('MatchingEngine: unhandled rejection', { reason: String(r) }); process.exit(1); });

  logger.info('MatchingEngine: running — waiting for transactions');
}

main().catch((err) => { console.error('MatchingEngine: fatal startup error', err.message); process.exit(1); });
