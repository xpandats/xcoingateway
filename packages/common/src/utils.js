'use strict';

/**
 * @module @xcg/common/utils
 *
 * Shared utility functions used across all services.
 */

const mongoose = require('mongoose');

const OBJECT_ID_REGEX = /^[a-f\d]{24}$/i;

/**
 * Validate that a string is a valid MongoDB ObjectId.
 * MUST be called before any DB query using an ID from external input.
 *
 * @param {string} id - The ID to validate
 * @returns {boolean} true if valid 24-char hex ObjectId
 */
function isValidObjectId(id) {
  return typeof id === 'string' && OBJECT_ID_REGEX.test(id);
}

/**
 * Assert that id is a valid ObjectId, throw AppError if not.
 * Use this before every `findById()` or `findOne({ _id })` call.
 *
 * @param {string} id - The ID to validate
 * @param {string} [label='ID'] - Field name for error message
 * @throws {AppError} 400 if invalid
 */
function validateObjectId(id, label = 'ID') {
  if (!isValidObjectId(id)) {
    // Import lazily to avoid circular dependency
    const AppError = require('./errors/AppError');
    throw AppError.badRequest(`Invalid ${label} format`, 'INVALID_ID_FORMAT');
  }
}

/**
 * Convert a string ID to a Mongoose ObjectId safely.
 * Validates first — throws if invalid.
 *
 * @param {string} id
 * @returns {mongoose.Types.ObjectId}
 */
function toObjectId(id) {
  validateObjectId(id);
  return new mongoose.Types.ObjectId(id);
}

/**
 * Return a safe MongoDB sort object from validated inputs.
 * Prevents injection via sortBy/sortOrder query params.
 *
 * @param {string} sortBy - Field name (must be pre-validated against whitelist)
 * @param {string} sortOrder - 'asc' or 'desc'
 * @returns {object} Mongoose sort object
 */
function buildSort(sortBy, sortOrder) {
  const direction = sortOrder === 'asc' ? 1 : -1;
  return { [sortBy]: direction };
}

module.exports = { isValidObjectId, validateObjectId, toObjectId, buildSort };
