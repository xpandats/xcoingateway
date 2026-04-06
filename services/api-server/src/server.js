'use strict';

/**
 * @module api-server/server
 *
 * Server Entry Point — Bank-Grade Startup.
 *
 * Startup sequence:
 *   1. Validate configuration (all secrets present, entropy correct, unique)
 *   2. Validate master encryption key
 *   3. Connect to MongoDB
 *   4. Connect to Redis (for nonce deduplication + rate limit store)
 *   5. Create Express app with Redis injected
 *   6. Start HTTP server
 *   7. Start invoice expiry scheduler
 *   8. Register graceful shutdown handlers
 *   9. Remove secrets from process.env (SC-3)
 */

const { config, validateConfig }  = require('./config');
const { createLogger }             = require('@xcg/logger');
const { validateMasterKey }        = require('@xcg/crypto');
const { connectDB, disconnectDB }  = require('@xcg/database');
const { createApp }                = require('./app');
const { createPublisher, QUEUES }  = require('@xcg/queue');
const { createRedisClient }        = require('@xcg/common/src/redisFactory');
const { mongoBreaker, tronBreaker } = require('@xcg/common/src/circuitBreaker');


const logger = createLogger('api-server');

// ─── Invoice Expiry Scheduler ────────────────────────────────────────────────
// Note: Invoice expiry is now handled by the Matching Engine's InvoiceExpiryScanner
// (services/matching-engine/src/invoiceExpiry.js) which fires payment.expired
// webhooks per-invoice. No duplicate scheduler needed here.


// ─── Main Startup ────────────────────────────────────────────────────────────

async function startServer() {
  try {
    // 1. Validate configuration
    logger.info('Validating configuration...');
    validateConfig();
    logger.info('Configuration validated', {
      env:         config.env,
      networkMode: config.networkMode,
      network:     config.tron.network,
    });

    // 2. Validate master encryption key format
    logger.info('Validating master encryption key...');
    validateMasterKey();
    logger.info('Master encryption key validated');

    // 3. Connect to MongoDB
    logger.info('Connecting to MongoDB...');
    await connectDB(config.db.uri, logger);
    logger.info('MongoDB connected');

    // 4. Connect to Redis
    // Gap 5: Use createRedisClient() which supports REDIS_MODE=standalone|sentinel|cluster.
    // Switch to sentinel in production by setting:
    //   REDIS_MODE=sentinel
    //   REDIS_SENTINEL_HOSTS=sentinel1:26379,sentinel2:26379,sentinel3:26379
    //   REDIS_SENTINEL_NAME=mymaster
    logger.info(`Connecting to Redis (mode: ${process.env.REDIS_MODE || 'standalone'})...`);
    const redis = createRedisClient({ logger });
    await new Promise((resolve, reject) => {
      redis.once('ready', resolve);
      redis.once('error', reject);
    });
    logger.info('Redis connected');


    // 4b. Set up queue publishers (for inter-service event publishing)
    const redisOpts = {
      host: new URL(config.redis.url).hostname,
      port: Number(new URL(config.redis.url).port) || 6379,
    };
    const paymentCreatedPublisher = createPublisher(
      QUEUES.PAYMENT_CREATED, redisOpts, config.queue.signingSecret, logger,
    );
    // Publisher for withdrawal.eligible — triggers withdrawal engine for manual withdrawal requests
    const withdrawalEligiblePublisher = createPublisher(
      QUEUES.WITHDRAWAL_ELIGIBLE, redisOpts, config.queue.signingSecret, logger,
    );

    // 4d. Circuit breaker monitoring (Gap 6)
    // mongoBreaker and tronBreaker are singleton instances defined in @xcg/common.
    // Any service wrapping DB or TronGrid calls via these breakers will emit events here.
    // We hook the events to fire SYSTEM_ALERT so ops is notified within seconds.
    const alertPublisher = createPublisher(
      QUEUES.SYSTEM_ALERT, redisOpts, config.queue.signingSecret, logger,
    );
    const authService = require('./services/authService');
    authService.setAlertPublisher(alertPublisher);
    logger.info('Alert publisher wired into authService');

    mongoBreaker.on('open', ({ name }) => {
      logger.error('CircuitBreaker: MongoDB OPEN — all DB calls will fast-fail', { name });
      alertPublisher.publish(
        { type: 'circuit_open', dependency: name, message: 'MongoDB circuit breaker OPENED. DB is unhealthy. API returning 503.' },
        `alert:circuit:${name}:open`,
      ).catch(() => {});
    });
    mongoBreaker.on('close', ({ name }) => {
      logger.info('CircuitBreaker: MongoDB CLOSED — database recovered', { name });
      alertPublisher.publish(
        { type: 'circuit_close', dependency: name, message: 'MongoDB circuit breaker CLOSED. Database has recovered.' },
        `alert:circuit:${name}:close`,
      ).catch(() => {});
    });

    tronBreaker.on('open', ({ name }) => {
      logger.error('CircuitBreaker: TronGrid OPEN — blockchain calls will fast-fail', { name });
      alertPublisher.publish(
        { type: 'circuit_open', dependency: name, message: 'TronGrid circuit breaker OPENED. Blockchain reads are failing.' },
        `alert:circuit:${name}:open`,
      ).catch(() => {});
    });
    tronBreaker.on('close', ({ name }) => {
      logger.info('CircuitBreaker: TronGrid CLOSED — blockchain API recovered', { name });
      alertPublisher.publish(
        { type: 'circuit_close', dependency: name, message: 'TronGrid circuit breaker CLOSED. Blockchain API has recovered.' },
        `alert:circuit:${name}:close`,
      ).catch(() => {});
    });

    // 5. Create Express app with Redis + publishers injected
    const app = createApp(redis, paymentCreatedPublisher, withdrawalEligiblePublisher);

    // 6. Start HTTP server
    const server = app.listen(config.port, () => {
      logger.info('API Server started', {
        port:        config.port,
        env:         config.env,
        networkMode: config.networkMode,
        network:     config.tron.network,
        pid:         process.pid,
      });
    });

    // Network security settings
    server.timeout        = 30_000;  // F2: Prevents Slowloris attacks
    server.requestTimeout = 30_000;
    server.keepAliveTimeout = 65_000; // Must be > LB idle timeout (typically 60s)

    // NOTE: Invoice expiry is now owned by Matching Engine (fires per-invoice webhooks)
    // SC-3: Remove secrets from process.env after startup
    // config.js and crypto modules have already cached values they need
    const SECRET_KEYS = [
      'MASTER_ENCRYPTION_KEY', 'JWT_ACCESS_SECRET', 'JWT_REFRESH_SECRET',
      'HMAC_SECRET', 'QUEUE_SIGNING_SECRET', 'WEBHOOK_SECRET',
    ];
    SECRET_KEYS.forEach((k) => { delete process.env[k]; });
    logger.info('SC-3: Secrets removed from process.env');

    // 8b. ServiceHealthSnapshot — persist health state every 60s for dashboard time-series
    const { ServiceHealthSnapshot } = require('@xcg/database');
    const { isDBConnected } = require('@xcg/database');
    const mongoose = require('mongoose');
    const healthInterval = setInterval(async () => {
      try {
        const memory = process.memoryUsage();
        const dbHealthy = isDBConnected() && mongoose.connection.readyState === 1;
        let redisHealthy = false;
        try { redisHealthy = (await redis.ping()) === 'PONG'; } catch { /* noop */ }

        await ServiceHealthSnapshot.create({
          serviceName:  'api-server',
          status:       (dbHealthy && redisHealthy) ? 'healthy' : 'degraded',
          checkedAt:    new Date(),
          dependencies: {
            mongodb: { status: dbHealthy ? 'healthy' : 'down' },
            redis:   { status: redisHealthy ? 'healthy' : 'down' },
          },
          metrics: {
            uptime:     Math.floor(process.uptime()),
            heapUsedMb: Math.round(memory.heapUsed / 1048576),
            heapTotalMb:Math.round(memory.heapTotal / 1048576),
            rssMb:      Math.round(memory.rss / 1048576),
          },
        });
      } catch { /* Never let health persistence crash the server */ }
    }, 60_000); // Every 60 seconds

    // 8. Graceful shutdown
    const shutdown = async (signal) => {
      logger.info(`${signal} received — starting graceful shutdown`);
      clearInterval(healthInterval); // Stop health snapshot persistence

      server.close(async () => {
        logger.info('HTTP server closed');
        try {
          await redis.quit();
          logger.info('Redis disconnected');
          await disconnectDB();
          logger.info('MongoDB disconnected');
        } catch (e) {
          logger.error('Shutdown error', { error: e.message });
        }
        logger.info('Graceful shutdown complete');
        process.exit(0);
      });

      // Force kill after 30 seconds
      setTimeout(() => {
        logger.error('Forced shutdown — timeout exceeded');
        process.exit(1);
      }, 30_000);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT',  () => shutdown('SIGINT'));

    process.on('unhandledRejection', (reason) => {
      logger.error('Unhandled rejection', { error: String(reason) });
    });

    process.on('uncaughtException', (err) => {
      logger.error('Uncaught exception — shutting down', { error: err.message, stack: err.stack });
      process.exit(1);
    });

  } catch (err) {
    logger.error('Failed to start API Server', { error: err.message, stack: err.stack });
    process.exit(1);
  }
}

startServer();
