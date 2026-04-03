'use strict';

/**
 * Admin IP Whitelist Middleware.
 *
 * Restricts admin-only routes to whitelisted IP addresses.
 * Applies to all routes mounted under admin namespace.
 *
 * SECURITY: This is a defense-in-depth layer. Even if an attacker
 * compromises admin credentials, they can't use them from a non-whitelisted IP.
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

    const clientIp = req.ip;

    // Normalize IPv6-mapped IPv4 (::ffff:127.0.0.1 → 127.0.0.1)
    const normalizedIp = clientIp.replace(/^::ffff:/, '');

    const isAllowed = allowedIps.some((ip) => {
      const normalizedAllowed = ip.replace(/^::ffff:/, '');
      return normalizedIp === normalizedAllowed || normalizedIp === ip;
    });

    if (!isAllowed) {
      logger.warn('Admin access denied — IP not whitelisted', {
        requestId: req.requestId,
        ip: clientIp,
        normalizedIp,
        path: req.path,
        whitelist: allowedIps,
      });

      // Intentionally vague error (don't reveal that IP whitelisting exists)
      throw AppError.forbidden('Access denied');
    }

    next();
  };
}

module.exports = { adminIpWhitelist };
