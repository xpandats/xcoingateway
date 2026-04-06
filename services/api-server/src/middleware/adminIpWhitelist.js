'use strict';

/**
 * Admin IP Whitelist Middleware.
 *
 * Restricts admin-only routes to whitelisted IP addresses.
 * Applies to all routes mounted under admin namespace.
 *
 * SECURITY: This is a defense-in-depth layer. Even if an attacker
 * compromises admin credentials, they can't use them from a non-whitelisted IP.
 *
 * GAP 6 FIX: Previous version used `throw AppError.forbidden()` inside a
 * synchronous Express middleware closure. Express does NOT catch synchronous
 * throws inside middleware returned by a factory function — the throw bubbles
 * past Express's error handling and hits the unhandled exception logger,
 * resulting in a 500 (Internal Server Error) instead of the intended 403.
 * Fix: Use `return next(AppError.forbidden(...))` for correct error propagation.
 */

const { AppError } = require('@xcg/common');
const { createLogger } = require('@xcg/logger');
const { config } = require('../config');

const logger = createLogger('security');

/**
 * Middleware factory: restrict access to whitelisted IPs.
 * @param {string[]} [whitelist] - Optional override of config whitelist
 * @returns {Function} Express middleware
 */
function adminIpWhitelist(whitelist = null) {
  const allowedIps = whitelist || config.admin.ipWhitelist;

  return (req, res, next) => {
    // Skip in dev if whitelist is not configured
    if (config.env === 'development' && allowedIps.length === 0) {
      return next();
    }

    const clientIp = req.ip || '';

    // Normalize IPv6-mapped IPv4 (::ffff:127.0.0.1 → 127.0.0.1)
    const normalizedIp = clientIp.replace(/^::ffff:/, '');

    const isAllowed = allowedIps.some((ip) => {
      const normalizedAllowed = ip.replace(/^::ffff:/, '');
      return normalizedIp === normalizedAllowed || normalizedIp === ip;
    });

    if (!isAllowed) {
      logger.warn('Admin access denied — IP not whitelisted', {
        requestId:   req.requestId,
        ip:          clientIp,
        normalizedIp,
        path:        req.path,
        // Do NOT log the allowedIps list in production — reveals security config to log aggregators
        whitelistConfigured: allowedIps.length > 0,
      });

      // GAP 6 FIX: Must use next(err) — throwing inside middleware returned by a factory
      // bypasses Express error handling. The throw propagated to Node's uncaught exception
      // handler and was logged as a 500 instead of being routed to error middleware as a 403.
      // Intentionally vague error message (don't reveal IP whitelisting exists to caller).
      return next(AppError.forbidden('Access denied'));
    }

    next();
  };
}

module.exports = { adminIpWhitelist };
