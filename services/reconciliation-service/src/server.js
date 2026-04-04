'use strict';
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env.local') });

const { config, validateConfig }         = require('../../api-server/src/config');
const { connectDB }                       = require('@xcg/database');
const { createLogger }                    = require('@xcg/logger');
const { createPublisher, QUEUES }         = require('@xcg/queue');
const { TronAdapter }                     = require('@xcg/tron');
const { startHealthServer }               = require('@xcg/common/src/healthServer');
const IORedis                             = require('ioredis');
const mongoose                            = require('mongoose');
const Reconciler                          = require('./reconciler');

const logger = createLogger('reconciliation-service');

async function main() {
  logger.info('ReconciliationService: starting up');
  try { validateConfig(); } catch (err) { logger.error('ReconciliationService: config failed', { error: err.message }); process.exit(1); }

  await connectDB(config.db.uri, logger);
  const redis = new IORedis(config.redis.url, { maxRetriesPerRequest: null });
  redis.on('error', (err) => logger.error('ReconciliationService: Redis error', { error: err.message }));

  // Health check server (internal only — port 3096)
  startHealthServer({ port: 3096, service: 'reconciliation-service', mongoose, redis, logger });

  const redisOpts = { host: new URL(config.redis.url).hostname, port: Number(new URL(config.redis.url).port) || 6379 };

  const tronAdapter    = new TronAdapter({ network: config.tron.network, apiKey: config.tron.apiKey }, logger);
  const alertPublisher = createPublisher(QUEUES.SYSTEM_ALERT, redisOpts, config.queue.signingSecret, logger);

  const reconciler = new Reconciler({ tronAdapter, redis, alertPublisher, logger });
  reconciler.start();

  async function shutdown(signal) {
    logger.info(`ReconciliationService: ${signal}`);
    reconciler.stop();
    await redis.quit();
    process.exit(0);
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));
  process.on('uncaughtException', (err) => { logger.error('ReconciliationService: uncaught', { error: err.message }); process.exit(1); });
  process.on('unhandledRejection', (r) => { logger.error('ReconciliationService: rejection', { reason: String(r) }); process.exit(1); });

  logger.info('ReconciliationService: running — first check in 15 minutes');
}
main().catch((err) => { console.error('ReconciliationService: fatal', err.message); process.exit(1); });
