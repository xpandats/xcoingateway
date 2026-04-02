'use strict';

/**
 * AppError — Centralized application error class.
 * All errors in the system extend this class.
 * Ensures consistent error shape across all services.
 *
 * Properties:
 *   statusCode  — HTTP status code (e.g., 400, 401, 500)
 *   code        — Internal error code (e.g., 'AUTH_INVALID_CREDENTIALS')
 *   message     — Human-readable message (safe for client)
 *   isOperational — true = expected error (client mistake), false = bug/system failure
 *   details     — Optional extra data (validation errors, field names)
 */
class AppError extends Error {
  /**
   * @param {string} message - Human-readable error message (safe to expose to client)
   * @param {number} statusCode - HTTP status code
   * @param {string} code - Internal error code from ErrorCodes
   * @param {boolean} [isOperational=true] - true if this is an expected/client error
   * @param {object} [details=null] - Additional error context (validation errors, etc.)
   */
  constructor(message, statusCode, code, isOperational = true, details = null) {
    super(message);
    this.name = 'AppError';
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = isOperational;
    this.details = details;
    this.timestamp = new Date().toISOString();

    // Capture stack trace, excluding this constructor
    Error.captureStackTrace(this, this.constructor);
  }

  /**
   * Serialize error for API response.
   * NEVER expose stack traces or internal details in production.
   */
  toJSON() {
    const response = {
      error: {
        code: this.code,
        message: this.message,
        timestamp: this.timestamp,
      },
    };

    if (this.details) {
      response.error.details = this.details;
    }

    return response;
  }

  // --- Factory methods for common errors ---

  static badRequest(message = 'Bad request', code = 'BAD_REQUEST', details = null) {
    return new AppError(message, 400, code, true, details);
  }

  static unauthorized(message = 'Unauthorized', code = 'UNAUTHORIZED') {
    return new AppError(message, 401, code, true);
  }

  static forbidden(message = 'Forbidden', code = 'FORBIDDEN') {
    return new AppError(message, 403, code, true);
  }

  static notFound(message = 'Resource not found', code = 'NOT_FOUND') {
    return new AppError(message, 404, code, true);
  }

  static conflict(message = 'Conflict', code = 'CONFLICT') {
    return new AppError(message, 409, code, true);
  }

  static tooManyRequests(message = 'Too many requests', code = 'RATE_LIMITED') {
    return new AppError(message, 429, code, true);
  }

  static internal(message = 'Internal server error', code = 'INTERNAL_ERROR') {
    return new AppError(message, 500, code, false);
  }

  static serviceUnavailable(message = 'Service unavailable', code = 'SERVICE_UNAVAILABLE') {
    return new AppError(message, 503, code, false);
  }
}

module.exports = AppError;
