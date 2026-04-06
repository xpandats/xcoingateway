'use strict';

/**
 * @module reconciliation-service/server
 *
 * Reconciliation Service entry point.
 *
 * Starts the scheduled reconciler (every 15 minutes) and subscribes to the
 * Redis pub/sub trigger channel so admin can fire a manual run via the API.
 *
 * NOTE: Two Redis connections are required — ioredis subscriber connection
 * CANNOT be reused for regular commands while subscribed.
 */

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env.local') });

const { config, validateConfig }         = require('../../api-server/src/config');
const { connectDB }                       = require('@xcg/database');
const { createLogger }                    = require('@xcg/logger');
const { createPublisher, QUEUES }         = require('@xcg/queue');
const { TronAdapter }                     = require('@xcg/tron');
const { startHealthServer }               = require('@xcg/common/src/healthServer');
const { createRedisClient }               = require('@xcg/common/src/redisFactory');
const { registerShutdown, runMain }       = require('@xcg/common/src/shutdown');
const mongoose                            = require('mongoose');


const Reconciler                          = require('./reconciler');

const logger = createLogger('reconciliation-service');

async function main() {
  logger.info('ReconciliationService: starting up');
  try { validateConfig(); } catch (err) {
    logger.error('ReconciliationService: config failed', { error: err.message });
    process.exit(1);
  }

  await connectDB(config.db.uri, logger);

  // Primary Redis connection (regular commands: GET, SET, DEL, PUBLISH)
  // Gap 5: Sentinel/Cluster-aware via REDIS_MODE env
  const redis = createRedisClient({ logger });
  redis.on('error', (err) => logger.error('ReconciliationService: Redis error', { error: err.message }));

  // Dedicated subscriber connection:
  // ioredis requires a separate connection for subscribe() — once subscribed,
  // the connection cannot be used for regular commands.
  const redisSub = createRedisClient({ logger });
  redisSub.on('error', (err) => logger.error('ReconciliationService: RedisSub error', { error: err.message }));


  // Health check server (internal only — port 3096)
  startHealthServer({ port: 3096, service: 'reconciliation-service', mongoose, redis, logger });

  const redisOpts = {
    host: new URL(config.redis.url).hostname,
    port: Number(new URL(config.redis.url).port) || 6379,
  };

  const tronAdapter    = new TronAdapter({ network: config.tron.network, apiKey: config.tron.apiKey }, logger);
  const alertPublisher = createPublisher(QUEUES.SYSTEM_ALERT, redisOpts, config.queue.signingSecret, logger);

  const reconciler = new Reconciler({
    tronAdapter,
    redis,        // Regular commands (GET/SET/DEL pause keys)
    redisSub,     // Dedicated subscriber for manual trigger channel
    alertPublisher,
    logger,
  });

  reconciler.start();

  registerShutdown({
    logger,
    service: 'reconciliation-service',
    cleanup: async () => {
      reconciler.stop();
      await redis.quit();
      await redisSub.quit();
    },
  });

  logger.info('ReconciliationService: running — first scheduled check in 15 minutes. Manual trigger ready on Redis pub/sub.');
}

runMain(main, { logger, service: 'reconciliation-service' });

