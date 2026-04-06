'use strict';

/**
 * @module @xcg/common
 *
 * Shared utilities for the XCoinGateway monorepo.
 * Single entry point for all common packages.
 *
 * NOTE: services can still use deep imports (e.g. require('@xcg/common/src/shutdown')).
 * This index provides a convenient flat namespace for common use.
 */

const AppError = require('./src/errors/AppError');
const { HttpStatus, ErrorCodes } = require('./src/errors/codes');
const constants = require('./src/constants');
const rbac = require('./src/rbac');
const { isSuperAdmin, canModifyUser } = require('./src/rbac');
const { validate, schemas } = require('./src/validation');
const response = require('./src/response');
const {
  getRequestContext,
  runWithContext,
  requestContextMiddleware,
  updateRequestContext,
} = require('./src/requestContext');
const { validateObjectId, toObjectId, buildSort, isValidObjectId } = require('./src/utils');
const money = require('./src/money');
const { safeFilePath } = require('./src/safeFilePath');

// ── Infrastructure modules (added for consistency — previously deep-import only) ──
const { CircuitBreaker, CircuitOpenError, mongoBreaker, tronBreaker, STATE: CB_STATE } = require('./src/circuitBreaker');
const { createRedisClient, createBullMQConnection } = require('./src/redisFactory');
const { registerShutdown, runMain, FORCE_KILL_TIMEOUT_MS } = require('./src/shutdown');
const { startHealthServer } = require('./src/healthServer');
const { createHealthHandler } = require('./src/healthCheck');
const fraudEngine = require('./src/fraudEngine');

module.exports = {
  // Errors
  AppError,
  HttpStatus,
  ErrorCodes,

  // Config & constants
  constants,

  // Validation
  validate,
  schemas,

  // RBAC
  rbac,
  isSuperAdmin,
  canModifyUser,

  // Response envelope
  response,

  // Request context (CLS)
  getRequestContext,
  runWithContext,
  requestContextMiddleware,
  updateRequestContext,

  // Utility functions
  validateObjectId,
  toObjectId,
  buildSort,
  isValidObjectId,

  // BL-5: Safe financial arithmetic (always use instead of +/-/* on money)
  money,

  // INJ-4: Path traversal prevention
  safeFilePath,

  // ── Infrastructure ──────────────────────────────────────────
  // Circuit Breaker
  CircuitBreaker,
  CircuitOpenError,
  mongoBreaker,
  tronBreaker,
  CB_STATE,

  // Redis factory (Standalone/Sentinel/Cluster)
  createRedisClient,
  createBullMQConnection,

  // Graceful shutdown
  registerShutdown,
  runMain,
  FORCE_KILL_TIMEOUT_MS,

  // Health checks & health server
  startHealthServer,
  createHealthHandler,

  // Fraud engine
  fraudEngine,
};

