'use strict';
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env.local') });

const { config, validateConfig }          = require('../../api-server/src/config');
const { connectDB }                        = require('@xcg/database');
const { createLogger }                     = require('@xcg/logger');
const { createConsumer, QUEUES }           = require('@xcg/queue');
const IORedis                              = require('ioredis');
const WebhookDeliveryEngine               = require('./webhookDelivery');
const AlertService                         = require('./alerts');

const logger = createLogger('notification-service');

async function main() {
  logger.info('NotificationService: starting up');
  try { validateConfig(); } catch (err) { logger.error('NotificationService: config failed', { error: err.message }); process.exit(1); }

  await connectDB(config.db.uri, logger);
  const redis = new IORedis(config.redis.url, { maxRetriesPerRequest: null });
  redis.on('error', (err) => logger.error('NotificationService: Redis error', { error: err.message }));

  const redisOpts = { host: new URL(config.redis.url).hostname, port: Number(new URL(config.redis.url).port) || 6379 };

  const webhookEngine = new WebhookDeliveryEngine({ logger });
  const alertService  = new AlertService({ botToken: config.telegram.botToken, chatId: config.telegram.chatId, logger });

  // Consume payment:confirmed → trigger webhook delivery
  const { worker: confirmWorker } = createConsumer(
    QUEUES.PAYMENT_CONFIRMED, redisOpts, config.queue.signingSecret, logger,
    (data, idempotencyKey) => webhookEngine.deliver({ ...data, event: data.event || 'payment.confirmed' }, `wh:${idempotencyKey}`),
    { concurrency: 10 },
  );

  // Consume system:alert → Telegram + log
  const { worker: alertWorker } = createConsumer(
    QUEUES.SYSTEM_ALERT, redisOpts, config.queue.signingSecret, logger,
    (data) => alertService.handle(data),
    { concurrency: 5 },
  );

  async function shutdown(signal) {
    logger.info(`NotificationService: ${signal}`);
    await confirmWorker.close();
    await alertWorker.close();
    await redis.quit();
    process.exit(0);
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));
  process.on('uncaughtException', (err) => { logger.error('NotificationService: uncaught', { error: err.message }); process.exit(1); });
  process.on('unhandledRejection', (r) => { logger.error('NotificationService: rejection', { reason: String(r) }); process.exit(1); });

  logger.info('NotificationService: running');
}
main().catch((err) => { console.error('NotificationService: fatal', err.message); process.exit(1); });
