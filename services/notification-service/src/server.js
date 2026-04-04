'use strict';
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env.local') });

const { config, validateConfig }               = require('../../api-server/src/config');
const { connectDB }                             = require('@xcg/database');
const { createLogger }                          = require('@xcg/logger');
const { createConsumer, createPublisher, QUEUES } = require('@xcg/queue');
const { startHealthServer }                     = require('@xcg/common/src/healthServer');
const IORedis                                   = require('ioredis');
const mongoose                                  = require('mongoose');
const WebhookDeliveryEngine                     = require('./webhookDelivery');
const AlertService                              = require('./alerts');

const logger = createLogger('notification-service');

async function main() {
  logger.info('NotificationService: starting up');
  try { validateConfig(); } catch (err) { logger.error('NotificationService: config failed', { error: err.message }); process.exit(1); }

  await connectDB(config.db.uri, logger);
  const redis = new IORedis(config.redis.url, { maxRetriesPerRequest: null });
  redis.on('error', (err) => logger.error('NotificationService: Redis error', { error: err.message }));

  // Health check server (internal only — port 3095)
  startHealthServer({ port: 3095, service: 'notification-service', mongoose, redis, logger });

  const redisOpts = {
    host: new URL(config.redis.url).hostname,
    port: Number(new URL(config.redis.url).port) || 6379,
  };

  const webhookEngine = new WebhookDeliveryEngine({ logger });
  const alertService  = new AlertService({
    botToken: config.telegram.botToken,
    chatId:   config.telegram.chatId,
    logger,
  });

  /**
   * Generic webhook dispatch handler.
   * Delivers any event that has event + merchantId fields.
   */
  const webhookDispatch = (data, idempotencyKey) =>
    webhookEngine.deliver({ ...data, event: data.event }, `wh:${idempotencyKey}`);

  // ── Payment CONFIRMED (matching engine → notification) ────────────────────
  const { worker: confirmWorker } = createConsumer(
    QUEUES.PAYMENT_CONFIRMED, redisOpts, config.queue.signingSecret, logger,
    webhookDispatch,
    { concurrency: 10 },
  );

  // ── Payment FAILED / EXPIRED (from matching engine + expiry scanner) ──────
  // One consumer handles payment.failed, payment.expired, underpayment, etc.
  const { worker: failedWorker } = createConsumer(
    QUEUES.PAYMENT_FAILED, redisOpts, config.queue.signingSecret, logger,
    webhookDispatch,
    { concurrency: 10 },
  );

  // ── Payment CREATED (from API server when invoice is created) ─────────────
  const { worker: createdWorker } = createConsumer(
    QUEUES.PAYMENT_CREATED, redisOpts, config.queue.signingSecret, logger,
    webhookDispatch,
    { concurrency: 10 },
  );

  // ── System alerts → Telegram + log ────────────────────────────────────────
  const { worker: alertWorker } = createConsumer(
    QUEUES.SYSTEM_ALERT, redisOpts, config.queue.signingSecret, logger,
    (data) => alertService.handle(data),
    { concurrency: 5 },
  );

  async function shutdown(signal) {
    logger.info(`NotificationService: ${signal}`);
    await confirmWorker.close();
    await failedWorker.close();
    await createdWorker.close();
    await alertWorker.close();
    await redis.quit();
    process.exit(0);
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));
  process.on('uncaughtException',  (err) => { logger.error('NotificationService: uncaught', { error: err.message }); process.exit(1); });
  process.on('unhandledRejection', (r)   => { logger.error('NotificationService: rejection', { reason: String(r) }); process.exit(1); });

  logger.info('NotificationService: running — consuming PAYMENT_CONFIRMED, PAYMENT_FAILED, PAYMENT_CREATED, SYSTEM_ALERT');
}
main().catch((err) => { console.error('NotificationService: fatal', err.message); process.exit(1); });
