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

const { config, validateConfig }   = require('../../api-server/src/config');
const { connectDB }                 = require('@xcg/database');
const { createLogger }              = require('@xcg/logger');
const { TronAdapter }               = require('@xcg/tron');
const { createPublisher, QUEUES }   = require('@xcg/queue');
const { startHealthServer }         = require('@xcg/common/src/healthServer');
const { createRedisClient }         = require('@xcg/common/src/redisFactory');
const { registerShutdown, runMain } = require('@xcg/common/src/shutdown');
const mongoose                      = require('mongoose');
const BlockchainListener            = require('./listener');
const { LeaderElection }            = require('./leaderElection');




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

  // 3. Connect to Redis (Gap 5: Sentinel/Cluster-aware via REDIS_MODE env)
  const redis = createRedisClient({ logger });
  redis.on('error', (err) => {
    logger.error('BlockchainListener: Redis error', { error: err.message });
  });


  // Health check server (internal only — port 3092)
  startHealthServer({ port: 3092, service: 'blockchain-listener', mongoose, redis, logger });

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

  // Gap 1 fix: Leader election — only ONE instance polls TronGrid at any time.
  //
  // If multiple replicas are deployed (rolling deploy, PM2 cluster, k8s HPA),
  // the elected leader polls blocks; standby replicas wait silently.
  // On leader crash, the Redis lock TTL expires (30s max) and a standby takes over.
  // On graceful shutdown, the lock is released immediately for sub-5s failover.
  //
  // FAIL-OPEN: If Redis is unavailable, ALL instances start polling.
  // The matching engine's seen-set deduplication prevents double-credit in this case.
  const leader = new LeaderElection({ redis, logger });

  leader.on('elected', async () => {
    logger.info('BlockchainListener: this instance is the leader — starting polling loop');
    await listener.start();
  });

  leader.on('deposed', () => {
    logger.info('BlockchainListener: lost leadership — stopping polling loop (standby mode)');
    listener.stop();
  });

  leader.start();


  registerShutdown({
    logger,
    service: 'blockchain-listener',
    cleanup: async () => {
      listener.stop();
      await leader.stop(); // Release leader lock — standby takes over immediately
      await redis.quit();
    },
  });
}

runMain(main, { logger, service: 'blockchain-listener' });

