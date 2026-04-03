'use strict';

/**
 * @module @xcg/common/response
 *
 * Standardized API response builder.
 *
 * Bank-grade requirement: Every response from every endpoint
 * MUST have the same top-level shape so clients never guess.
 *
 * Success: { success: true, data: {...}, message?: '...' }
 * Error:   { success: false, error: { code, message, details?, timestamp } }
 * Paged:   { success: true, data: [...], pagination: { page, limit, total, pages, hasMore } }
 */

/**
 * Build a standard success response.
 *
 * @param {object} [data=null] - Response payload
 * @param {string} [message=null] - Optional human-readable message
 * @returns {object} Standardized success envelope
 */
function success(data = null, message = null) {
  const response = { success: true };
  if (data !== null && data !== undefined) response.data = data;
  if (message) response.message = message;
  return response;
}

/**
 * Build a standard error response.
 *
 * @param {string} code - Machine-readable error code (from ErrorCodes)
 * @param {string} message - Human-readable error message (safe for client)
 * @param {*} [details=null] - Optional validation error details
 * @returns {object} Standardized error envelope
 */
function error(code, message, details = null) {
  const response = {
    success: false,
    error: {
      code,
      message,
      timestamp: new Date().toISOString(),
    },
  };
  if (details) response.error.details = details;
  return response;
}

/**
 * Build a paginated success response.
 *
 * @param {Array} items - Array of records
 * @param {number} total - Total matching records (across all pages)
 * @param {number} page - Current page number (1-based)
 * @param {number} limit - Records per page
 * @param {string} [message=null] - Optional message
 * @returns {object} Standardized paginated envelope
 */
function paginated(items, total, page, limit, message = null) {
  const pages = Math.ceil(total / limit);
  const response = {
    success: true,
    data: items,
    pagination: {
      page,
      limit,
      total,
      pages,
      hasMore: page < pages,
    },
  };
  if (message) response.message = message;
  return response;
}

/**
 * Build a no-content success response (for DELETE, etc.)
 *
 * @param {string} [message='Operation completed successfully'] - Message
 * @returns {object} Standardized success envelope without data
 */
function noContent(message = 'Operation completed successfully') {
  return { success: true, message };
}

module.exports = { success, error, paginated, noContent };
