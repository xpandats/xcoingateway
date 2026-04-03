'use strict';

/**
 * @module middleware/originValidation
 *
 * CSRF-2: Server-Side Origin Validation.
 *
 * WHY NEEDED IN ADDITION TO CORS:
 *   CORS is enforced by the BROWSER. It doesn't protect against:
 *   - Requests from `curl`, Postman, or server-side code
 *   - Browsers with broken CORS implementations
 *   - CSRF via form submission with Content-Type: application/json
 *     (some old browser bugs allow this)
 *
 * This middleware independently validates the Origin header for all
 * state-mutation requests (POST, PUT, PATCH, DELETE).
 *
 * CSRF-1 MITIGATION: All mutation endpoints check Origin independently.
 * Combined with sameSite: 'strict' on cookies = full CSRF protection.
 *
 * Note: GET requests are excluded (they should be idempotent and safe).
 */

const { createLogger } = require('@xcg/logger');
const { AppError } = require('@xcg/common');
const { config } = require('../config');

const logger = createLogger('security');

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Get the allowlist of origins from config.
 * Computed once and cached.
 */
function _getAllowedOrigins() {
  if (config.env === 'production') {
    return (process.env.ALLOWED_ORIGINS || '').split(',').map((o) => o.trim()).filter(Boolean);
  }
  return ['http://localhost:3000', 'http://localhost:5173', 'http://127.0.0.1:3000', 'http://127.0.0.1:5173'];
}

let _cachedAllowedOrigins = null;

/**
 * Origin validation middleware.
 *
 * For mutation requests: require Origin or Referer header to match allowlist.
 * Server-to-server API requests (merchant HMAC) skip this check.
 */
function validateOrigin(req, _res, next) {
  // Skip safe HTTP methods
  if (SAFE_METHODS.has(req.method)) return next();

  // Skip if request was authenticated via HMAC (server-to-server, no browser origin)
  if (req.merchant) return next();

  // Skip Postman/curl in development (no Origin header = programmatic access)
  // In production, Origin MUST be present for browser requests
  const origin = req.headers.origin || req.headers.referer;

  if (!origin) {
    if (config.env === 'production') {
      logger.warn('CSRF: Mutation request with no Origin header in production', {
        requestId: req.requestId,
        method: req.method,
        path: req.path,
        ip: req.ip,
      });
      // In production, reject requests with no origin for mutation endpoints
      // Exception: Internal service calls should use HMAC auth (caught above)
      return next(AppError.forbidden('Origin header required for mutation requests'));
    }
    // Dev: allow programmatic access without origin (Postman, curl, tests)
    return next();
  }

  if (!_cachedAllowedOrigins) {
    _cachedAllowedOrigins = _getAllowedOrigins();
  }

  // Check if origin matches (prefix match for referer which includes path)
  const isAllowed = _cachedAllowedOrigins.some((allowed) => origin.startsWith(allowed));

  if (!isAllowed) {
    logger.warn('CSRF: Origin validation failed', {
      requestId: req.requestId,
      origin,
      method: req.method,
      path: req.path,
      ip: req.ip,
    });
    return next(AppError.forbidden('Origin not allowed'));
  }

  next();
}

module.exports = { validateOrigin };
