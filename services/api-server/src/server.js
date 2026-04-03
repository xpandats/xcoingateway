'use strict';

/**
 * Server Entry Point.
 *
 * Startup sequence:
 *   1. Validate configuration
 *   2. Validate master encryption key
 *   3. Connect to MongoDB
 *   4. Start Express server
 *   5. Register graceful shutdown handlers
 */

const { config, validateConfig } = require('./config');
const { createLogger } = require('@xcg/logger');
const { validateMasterKey } = require('@xcg/crypto');
const { connectDB, disconnectDB } = require('@xcg/database');
const app = require('./app');

const logger = createLogger('api-server');

async function startServer() {
  try {
    // 1. Validate configuration
    logger.info('Validating configuration...');
    validateConfig();
    logger.info('Configuration validated', { env: config.env, networkMode: config.networkMode });

    // 2. Validate master encryption key
    logger.info('Validating master encryption key...');
    validateMasterKey();
    logger.info('Master encryption key validated');

    // 3. Connect to MongoDB
    logger.info('Connecting to MongoDB...');
    await connectDB(config.db.uri);

    // 4. Start Express server
    const server = app.listen(config.port, () => {
      logger.info('API Server started', {
        port: config.port,
        env: config.env,
        networkMode: config.networkMode,
        pid: process.pid,
      });
    });

    // F2: Prevent Slowloris attacks — kill connections that take too long
    server.timeout = 30000;          // 30s total request timeout
    server.requestTimeout = 30000;   // 30s for request header parsing
    server.keepAliveTimeout = 65000; // 65s (must be > LB idle timeout)

    // 5. Graceful shutdown
    const shutdown = async (signal) => {
      logger.info(`${signal} received. Starting graceful shutdown...`);

      // Stop accepting new connections
      server.close(async () => {
        logger.info('HTTP server closed');

        // Disconnect from database
        await disconnectDB();
        logger.info('Database disconnected');

        logger.info('Graceful shutdown complete');
        process.exit(0);
      });

      // Force shutdown after 30 seconds
      setTimeout(() => {
        logger.error('Forced shutdown — graceful shutdown timed out');
        process.exit(1);
      }, 30000);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));

    // Catch unhandled rejections (log + stay alive)
    process.on('unhandledRejection', (reason) => {
      logger.error('Unhandled Promise Rejection', { error: reason?.message || reason });
    });

    // Catch uncaught exceptions (log + shutdown)
    process.on('uncaughtException', (err) => {
      logger.error('Uncaught Exception — shutting down', { error: err.message, stack: err.stack });
      process.exit(1);
    });

  } catch (err) {
    logger.error('Failed to start API Server', { error: err.message, stack: err.stack });
    process.exit(1);
  }
}

startServer();
