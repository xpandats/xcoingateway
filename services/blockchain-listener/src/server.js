'use strict';

/**
 * @module blockchain-listener/server
 *
 * Blockchain Listener — Service Entry Point.
 *
 * Startup sequence:
 *   1. Load + validate config
 *   2. Connect to MongoDB
 *   3. Connect to Redis
 *   4. Initialise TronAdapter
 *   5. Create queue publishers
 *   6. Start BlockchainListener polling loop
 *   7. Register graceful shutdown handlers
 */

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env.local') });

const { config, validateConfig } = require('../../api-server/src/config');
const { connectDB }              = require('@xcg/database');
const { createLogger }           = require('@xcg/logger');
const { TronAdapter }            = require('@xcg/tron');
const { createPublisher, QUEUES } = require('@xcg/queue');
const IORedis                    = require('ioredis');
const BlockchainListener         = require('./listener');

const logger = createLogger('blockchain-listener');

async function main() {
  logger.info('BlockchainListener: starting up...');

  // 1. Validate config (throws on missing secrets)
  try {
    validateConfig();
  } catch (err) {
    logger.error('BlockchainListener: config validation failed', { error: err.message });
    process.exit(1);
  }

  // 2. Connect to MongoDB
  await connectDB(config.db.uri, logger);

  // 3. Connect to Redis
  const redis = new IORedis(config.redis.url, {
    maxRetriesPerRequest: null, // Required for BullMQ
    lazyConnect: false,
  });
  redis.on('error', (err) => {
    logger.error('BlockchainListener: Redis error', { error: err.message });
  });

  // 4. Initialise TronAdapter
  const tronAdapter = new TronAdapter(
    { network: config.tron.network, apiKey: config.tron.apiKey },
    logger,
  );

  // 5. Create queue publishers
  const redisOpts = { host: new URL(config.redis.url).hostname, port: Number(new URL(config.redis.url).port) || 6379 };

  const txPublisher = createPublisher(
    QUEUES.TRANSACTION_DETECTED,
    redisOpts,
    config.queue.signingSecret,
    logger,
  );
  const alertPublisher = createPublisher(
    QUEUES.SYSTEM_ALERT,
    redisOpts,
    config.queue.signingSecret,
    logger,
  );

  // 6. Create and start listener
  const listener = new BlockchainListener({
    adapter:        tronAdapter,
    redis,
    publisher:      txPublisher,
    alertPublisher,
    config:         config.tron,
    logger,
  });

  await listener.start();

  // 7. Graceful shutdown
  async function shutdown(signal) {
    logger.info(`BlockchainListener: received ${signal} — shutting down`);
    listener.stop();
    await redis.quit();
    process.exit(0);
  }

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));

  process.on('uncaughtException', (err) => {
    logger.error('BlockchainListener: uncaught exception', { error: err.message, stack: err.stack });
    process.exit(1);
  });
  process.on('unhandledRejection', (reason) => {
    logger.error('BlockchainListener: unhandled rejection', { reason: String(reason) });
    process.exit(1);
  });
}

main().catch((err) => {
  console.error('BlockchainListener: fatal startup error', err.message);
  process.exit(1);
});
