'use strict';

/**
 * @module @xcg/common
 * Shared utilities for the XCoinGateway monorepo.
 * Exports: AppError, HttpStatus, ErrorCodes, constants, RBAC, validation schemas.
 */

const AppError = require('./src/errors/AppError');
const { HttpStatus, ErrorCodes } = require('./src/errors/codes');
const constants = require('./src/constants');
const rbac = require('./src/rbac');
const { validate, schemas } = require('./src/validation');

module.exports = {
  AppError,
  HttpStatus,
  ErrorCodes,
  constants,
  rbac,
  validate,
  schemas,
};
