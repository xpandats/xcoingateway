'use strict';

/**
 * @module withdrawal-engine/server
 * Entry point for the Withdrawal Engine.
 */

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env.local') });

const { config, validateConfig }               = require('../../api-server/src/config');
const { connectDB }                             = require('@xcg/database');
const { createLogger }                          = require('@xcg/logger');
const { createConsumer, createPublisher, QUEUES } = require('@xcg/queue');
const { startHealthServer }                     = require('@xcg/common/src/healthServer');
const IORedis                                   = require('ioredis');
const mongoose                                  = require('mongoose');
const TronAdapter                               = require('@xcg/tron').TronAdapter;
const WithdrawalProcessor                       = require('./processor');

const logger = createLogger('withdrawal-engine');

async function main() {
  logger.info('WithdrawalEngine: starting up');

  try { validateConfig(); } catch (err) {
    logger.error('WithdrawalEngine: config validation failed', { error: err.message });
    process.exit(1);
  }

  await connectDB(config.db.uri, logger);

  const redis = new IORedis(config.redis.url, { maxRetriesPerRequest: null });
  redis.on('error', (err) => logger.error('WithdrawalEngine: Redis error', { error: err.message }));

  // Health check server (internal only — port 3094)
  startHealthServer({ port: 3094, service: 'withdrawal-engine', mongoose, redis, logger });

  const redisOpts = {
    host: new URL(config.redis.url).hostname,
    port: Number(new URL(config.redis.url).port) || 6379,
  };

  const signingPublisher  = createPublisher(QUEUES.SIGNING_REQUEST,      redisOpts, config.queue.signingSecret, logger);
  const alertPublisher    = createPublisher(QUEUES.SYSTEM_ALERT,          redisOpts, config.queue.signingSecret, logger);
  // Self-publisher: allows processor to re-queue cooling-off withdrawals with BullMQ delay
  const selfPublisher     = createPublisher(QUEUES.WITHDRAWAL_ELIGIBLE,   redisOpts, config.queue.signingSecret, logger);

  // Tron adapter for energy checks
  const tronAdapter = new TronAdapter({
    network: config.tron.network,
    apiKey:  config.tron.apiKey,
  }, logger);

  const processor = new WithdrawalProcessor({
    signingPublisher,
    alertPublisher,
    tronAdapter,
    config:      config.wallet,
    tronNetwork: config.tron.network,
    logger,
  });

  // Also listen for signing:complete to update withdrawal status
  const signingCompletePublisher = createPublisher(QUEUES.PAYMENT_CONFIRMED, redisOpts, config.queue.signingSecret, logger);

  const { worker: eligibleWorker } = createConsumer(
    QUEUES.WITHDRAWAL_ELIGIBLE,
    redisOpts,
    config.queue.signingSecret,
    logger,
    (data, idempotencyKey) => processor.handle(data, idempotencyKey, selfPublisher), // Pass self-publisher
    { concurrency: 2 }, // Low concurrency — withdrawal is a critical path
  );

  const { worker: signingCompleteWorker } = createConsumer(
    QUEUES.SIGNING_COMPLETE,
    redisOpts,
    config.queue.signingSecret,
    logger,
    async (data) => {
      const { Withdrawal } = require('@xcg/database');
      if (!data.success || !data.txHash) return;
      await Withdrawal.findOneAndUpdate(
        { _id: data.withdrawalId }, // If withdrawalId is in payload
        { $set: { status: 'broadcast', txHash: data.txHash, broadcastAt: new Date() } },
      );
      logger.info('WithdrawalEngine: withdrawal broadcast confirmed', { txHash: data.txHash });
    },
    { concurrency: 5 },
  );

  async function shutdown(signal) {
    logger.info(`WithdrawalEngine: ${signal}`);
    await eligibleWorker.close();
    await signingCompleteWorker.close();
    await redis.quit();
    process.exit(0);
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));
  process.on('uncaughtException', (err) => { logger.error('WithdrawalEngine: uncaught', { error: err.message }); process.exit(1); });
  process.on('unhandledRejection', (r)  => { logger.error('WithdrawalEngine: rejection', { reason: String(r) }); process.exit(1); });

  logger.info('WithdrawalEngine: running');
}

main().catch((err) => { console.error('WithdrawalEngine: fatal', err.message); process.exit(1); });
