'use strict';

/**
 * MongoDB Connection Manager.
 *
 * Handles:
 *   - Connection with retry logic
 *   - Graceful disconnect on shutdown
 *   - Connection event monitoring
 *   - Separate connections per environment
 */

const mongoose = require('mongoose');
const { createLogger } = require('@xcg/logger');

const logger = createLogger('database');

let isConnected = false;

/**
 * Connect to MongoDB with retry logic.
 *
 * @param {string} [uri] - MongoDB URI (defaults to MONGODB_URI env var)
 * @param {object} [options] - Mongoose connection options
 * @returns {Promise<void>}
 */
async function connectDB(uri = null, options = {}) {
  const mongoUri = uri || process.env.MONGODB_URI;

  if (!mongoUri) {
    throw new Error('FATAL: MONGODB_URI is not set. Cannot connect to database.');
  }

  const defaultOptions = {
    maxPoolSize: 10,
    minPoolSize: 2,
    serverSelectionTimeoutMS: 5000,
    heartbeatFrequencyMS: 10000,
    retryWrites: true,
    ...options,
  };

  // Connection event handlers
  mongoose.connection.on('connected', () => {
    isConnected = true;
    logger.info('MongoDB connected', { uri: mongoUri.replace(/\/\/.*@/, '//<credentials>@') });
  });

  mongoose.connection.on('disconnected', () => {
    isConnected = false;
    logger.warn('MongoDB disconnected');
  });

  mongoose.connection.on('error', (err) => {
    logger.error('MongoDB connection error', { error: err.message });
  });

  // Retry connection with backoff
  const maxRetries = 5;
  let retries = 0;

  while (retries < maxRetries) {
    try {
      await mongoose.connect(mongoUri, defaultOptions);
      logger.info('MongoDB connection established successfully');
      return;
    } catch (err) {
      retries++;
      const delay = Math.min(1000 * Math.pow(2, retries), 30000); // Exponential backoff, max 30s
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
 * Call this during service shutdown.
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
