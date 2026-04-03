'use strict';

/**
 * @module @xcg/common
 *
 * Shared utilities for the XCoinGateway monorepo.
 * Single entry point for all common packages.
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

module.exports = {
  AppError,
  HttpStatus,
  ErrorCodes,
  constants,
  rbac,
  validate,
  schemas,
  response,
  getRequestContext,
  runWithContext,
  requestContextMiddleware,
  updateRequestContext,
  // Utility functions
  validateObjectId,
  toObjectId,
  buildSort,
  isValidObjectId,
  // RBAC helpers
  isSuperAdmin,
  canModifyUser,
};
