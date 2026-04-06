'use strict';

/**
 * @module @xcg/database/connection
 *
 * MongoDB Connection Manager — Bank-Grade.
 *
 * Features:
 *   - Connection with exponential backoff retry
 *   - Event listeners registered ONCE (no leak on reconnect)
 *   - Graceful disconnect on shutdown
 *   - Connection health monitoring
 *   - Circuit breaker integration (Gap 6): mongoBreaker opens instantly on
 *     disconnect and closes on reconnect, providing immediate fast-fail for
 *     all DB-dependent routes rather than waiting for individual query timeouts.
 */

const mongoose = require('mongoose');
const { createLogger } = require('@xcg/logger');

// Lazy-load: avoid circular dep and allow services that don't need the breaker
// (tests, migrations) to import this module without pulling in @xcg/common
let _mongoBreaker = null;
function getMongoBreaker() {
  if (!_mongoBreaker) {
    try {
      _mongoBreaker = require('@xcg/common/src/circuitBreaker').mongoBreaker;
    } catch {
      // @xcg/common not installed in this context — breaker stays null
    }
  }
  return _mongoBreaker;
}


const logger = createLogger('database');

let isConnected = false;
let listenersRegistered = false;

/**
 * Register connection event listeners ONCE.
 * Prevents listener stacking if connectDB() is called multiple times.
 */
function _registerListeners(uri) {
  if (listenersRegistered) return;
  listenersRegistered = true;

  // Redact credentials from URI for logging
  const safeUri = uri.replace(/\/\/.*@/, '//<credentials>@');

  mongoose.connection.on('connected', () => {
    isConnected = true;
    logger.info('MongoDB connected', { uri: safeUri });
    // Close circuit breaker on successful connection — traffic can flow
    const breaker = getMongoBreaker();
    if (breaker && breaker.isOpen) {
      // Manually transition OPEN → CLOSED (connection is ground-truth recovery signal)
      breaker._transitionTo('CLOSED');
      logger.info('MongoBreaker: circuit CLOSED — MongoDB has connected');
    }
  });

  mongoose.connection.on('disconnected', () => {
    isConnected = false;
    logger.warn('MongoDB disconnected');
    // Open circuit breaker immediately on disconnect — don't wait for 5 query timeouts.
    // A socket disconnect is a 100% reliable failure signal.
    const breaker = getMongoBreaker();
    if (breaker && !breaker.isOpen) {
      breaker._transitionTo('OPEN');
      logger.error('MongoBreaker: circuit OPENED — MongoDB disconnected. DB calls will fast-fail.');
    }
  });

  mongoose.connection.on('error', (err) => {
    logger.error('MongoDB connection error', { error: err.message });
  });

  mongoose.connection.on('reconnected', () => {
    isConnected = true;
    logger.info('MongoDB reconnected');
    // Close circuit on reconnect
    const breaker = getMongoBreaker();
    if (breaker && breaker.isOpen) {
      breaker._transitionTo('CLOSED');
      logger.info('MongoBreaker: circuit CLOSED — MongoDB reconnected');
    }
  });
}


/**
 * Connect to MongoDB with retry logic.
 *
 * @param {string} [uri]     - MongoDB URI (defaults to MONGODB_URI env var)
 * @param {object} [loggerOrOptions] - Logger instance OR Mongoose options object
 * @param {object} [options] - Mongoose connection options (if logger passed as 2nd param)
 * @returns {Promise<void>}
 * @throws {Error} After max retries exceeded
 */
async function connectDB(uri = null, loggerOrOptions = {}, options = {}) {
  const mongoUri = uri || process.env.MONGODB_URI;

  // Allow (uri, logger) or (uri, options) calling conventions
  // Detect if second param is a logger (has .info method) or options object
  let externalLogger = null;
  let mongoOptions   = options;
  if (loggerOrOptions && typeof loggerOrOptions.info === 'function') {
    externalLogger = loggerOrOptions; // It's a logger
    mongoOptions   = options;
  } else if (loggerOrOptions && typeof loggerOrOptions === 'object') {
    mongoOptions = loggerOrOptions; // It's options
  }

  const _log = (level, msg, meta) => {
    if (externalLogger && typeof externalLogger[level] === 'function') {
      externalLogger[level](msg, meta);
    } else {
      logger[level](msg, meta);
    }
  };

  if (!mongoUri) {
    throw new Error('FATAL: MONGODB_URI is not set. Cannot connect to database.');
  }

  // Register listeners ONCE before any connection attempt
  _registerListeners(mongoUri);

  const defaultOptions = {
    maxPoolSize: 10,
    minPoolSize: 2,
    serverSelectionTimeoutMS: 5000,
    heartbeatFrequencyMS: 10000,
    retryWrites: true,
    // F3: Kill queries taking longer than 10 seconds to prevent DoS via slow queries
    socketTimeoutMS: 45000,
    connectTimeoutMS: 10000,
    ...mongoOptions,
  };

  // F3: Global query timeout via Mongoose plugin
  const mongoose_module = require('mongoose');
  mongoose_module.set('maxTimeMS', 10000); // 10s max per query

  const maxRetries = 5;
  let retries = 0;

  while (retries < maxRetries) {
    try {
      await mongoose.connect(mongoUri, defaultOptions);
      _log('info', 'MongoDB connection established successfully');
      return;
    } catch (err) {
      retries++;
      const delay = Math.min(1000 * Math.pow(2, retries), 30000);
      _log('error', `MongoDB connection attempt ${retries}/${maxRetries} failed`, {
        error: err.message,
        retryInMs: delay,
      });

      if (retries === maxRetries) {
        throw new Error(`FATAL: Failed to connect to MongoDB after ${maxRetries} attempts`);
      }

      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
}

/**
 * Gracefully disconnect from MongoDB.
 */
async function disconnectDB() {
  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
    isConnected = false;
    logger.info('MongoDB disconnected gracefully');
  }
}

/**
 * Check if database is connected.
 * @returns {boolean}
 */
function isDBConnected() {
  return isConnected && mongoose.connection.readyState === 1;
}

module.exports = { connectDB, disconnectDB, isDBConnected };
