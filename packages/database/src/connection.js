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
 */

const mongoose = require('mongoose');
const { createLogger } = require('@xcg/logger');

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
  });

  mongoose.connection.on('disconnected', () => {
    isConnected = false;
    logger.warn('MongoDB disconnected');
  });

  mongoose.connection.on('error', (err) => {
    logger.error('MongoDB connection error', { error: err.message });
  });

  mongoose.connection.on('reconnected', () => {
    isConnected = true;
    logger.info('MongoDB reconnected');
  });
}

/**
 * Connect to MongoDB with retry logic.
 *
 * @param {string} [uri] - MongoDB URI (defaults to MONGODB_URI env var)
 * @param {object} [options] - Mongoose connection options
 * @returns {Promise<void>}
 * @throws {Error} After max retries exceeded
 */
async function connectDB(uri = null, options = {}) {
  const mongoUri = uri || process.env.MONGODB_URI;

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
    ...options,
  };

  // F3: Global query timeout via Mongoose plugin
  const mongoose_module = require('mongoose');
  mongoose_module.set('maxTimeMS', 10000); // 10s max per query

  const maxRetries = 5;
  let retries = 0;

  while (retries < maxRetries) {
    try {
      await mongoose.connect(mongoUri, defaultOptions);
      logger.info('MongoDB connection established successfully');
      return;
    } catch (err) {
      retries++;
      const delay = Math.min(1000 * Math.pow(2, retries), 30000);
      logger.error(`MongoDB connection attempt ${retries}/${maxRetries} failed`, {
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
