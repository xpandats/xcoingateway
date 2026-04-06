'use strict';

/**
 * @module @xcg/common/src/shutdown
 *
 * Graceful Shutdown — Consistent across ALL services.
 *
 * WHY THIS EXISTS:
 *   Before this utility, each service's shutdown handler was different:
 *   - 4 services were missing disconnectDB()
 *   - All worker services were missing the 30s force-kill timeout
 *   - 5 services used console.error in main().catch() instead of the logger
 *   - Mongoose connection pool leaks when containers receive SIGTERM
 *
 * USAGE:
 *   const { registerShutdown } = require('@xcg/common/src/shutdown');
 *
 *   registerShutdown({
 *     logger,
 *     service: 'matching-engine',
 *     cleanup: async () => {
 *       tracker.stop();
 *       worker.close();
 *       redis.quit();
 *     },
 *   });
 *
 * SHUTDOWN SEQUENCE (30s hard timeout):
 *   SIGTERM/SIGINT received
 *     → call cleanup()   (user-provided: close queues, stop pollers)
 *     → disconnectDB()   (close all Mongoose connection pool sockets)
 *     → process.exit(0)
 *   30s timeout → process.exit(1)
 */

const { disconnectDB } = require('@xcg/database');

const FORCE_KILL_TIMEOUT_MS = 30_000;

/**
 * Register unified signal handlers for a service.
 *
 * @param {object}   opts
 * @param {object}   opts.logger              - @xcg/logger instance
 * @param {string}   opts.service             - Service name (for log messages)
 * @param {Function} opts.cleanup             - Async function: stop workers, close Redis, etc.
 * @param {boolean}  [opts.skipDbDisconnect]  - Set true for services that don't use MongoDB (none currently)
 */
function registerShutdown({ logger, service, cleanup, skipDbDisconnect = false }) {
  let shutdownInitiated = false;

  async function shutdown(signal) {
    if (shutdownInitiated) return; // Prevent duplicate shutdown on SIGTERM + SIGINT
    shutdownInitiated = true;

    logger.info(`${service}: ${signal} received — starting graceful shutdown`);

    // Force-kill timeout — prevents zombie processes in Kubernetes/Docker
    const forceKill = setTimeout(() => {
      logger.error(`${service}: graceful shutdown timed out after ${FORCE_KILL_TIMEOUT_MS / 1000}s — forcing exit`);
      process.exit(1);
    }, FORCE_KILL_TIMEOUT_MS);
    // Do not let this timer keep the event loop alive
    forceKill.unref();

    try {
      // 1. Run service-specific cleanup (close BullMQ workers, stop pollers, etc.)
      if (typeof cleanup === 'function') {
        await cleanup();
        logger.info(`${service}: cleanup complete`);
      }

      // 2. Disconnect MongoDB (close connection pool sockets)
      if (!skipDbDisconnect) {
        try {
          await disconnectDB();
          logger.info(`${service}: MongoDB disconnected`);
        } catch (dbErr) {
          logger.warn(`${service}: MongoDB disconnect error (non-fatal)`, { error: dbErr.message });
        }
      }

      clearTimeout(forceKill);
      logger.info(`${service}: graceful shutdown complete`);
      process.exit(0);
    } catch (err) {
      logger.error(`${service}: shutdown error`, { error: err.message });
      clearTimeout(forceKill);
      process.exit(1);
    }
  }

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));

  // These are fatal — exit immediately but log structured
  process.on('uncaughtException', (err) => {
    logger.error(`${service}: uncaught exception — exiting`, {
      error: err.message,
      stack: err.stack,
    });
    process.exit(1);
  });

  process.on('unhandledRejection', (reason) => {
    logger.error(`${service}: unhandled rejection — exiting`, {
      reason: String(reason),
    });
    process.exit(1);
  });
}

/**
 * Wrap a service's main() function to log fatal startup errors via structured logger.
 * Replaces: main().catch(err => { console.error(...); process.exit(1); })
 * With:     runMain(main, { logger, service: 'my-service' })
 *
 * @param {Function} mainFn     - The async main() function
 * @param {object}   opts
 * @param {object}   opts.logger
 * @param {string}   opts.service
 */
function runMain(mainFn, { logger, service }) {
  mainFn().catch((err) => {
    // At fatal startup time, the logger may or may not be initialised yet.
    // Use both so the error is never lost.
    if (logger && typeof logger.error === 'function') {
      logger.error(`${service}: fatal startup error`, {
        error: err.message,
        stack: err.stack,
      });
    }
    // fallback so error appears in raw container output even if logger fails
    console.error(`[${service}] FATAL:`, err.message);
    process.exit(1);
  });
}

module.exports = { registerShutdown, runMain, FORCE_KILL_TIMEOUT_MS };
