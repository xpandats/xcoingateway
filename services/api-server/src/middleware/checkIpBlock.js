'use strict';

/**
 * @module middleware/checkIpBlock
 *
 * IP Blocklist Middleware — Checks IpBlocklist model before auth.
 *
 * PERFORMANCE:
 *   Redis cache (1-min TTL) → Avoids DB hit on every request.
 *   On cache miss → checks DB → caches result.
 *   When admin blocks an IP, the next request will miss cache within 1 min.
 *
 * WARNING: This middleware runs BEFORE authentication. It must never leak
 * why a request was blocked (no details in the 403 response).
 */

const { IpBlocklist } = require('@xcg/database');

const CACHE_PREFIX = 'xcg:ipblock:';
const CACHE_TTL    = 60; // 1 minute — balance between performance and responsiveness

/**
 * Build IP block-check middleware.
 * @param {object} opts
 * @param {object} opts.redis  - IORedis instance
 * @param {object} opts.logger - @xcg/logger instance
 * @returns {Function} Express middleware
 */
function checkIpBlock({ redis, logger }) {
  return async (req, res, next) => {
    const ip = req.ip || req.connection?.remoteAddress || '';
    if (!ip) return next(); // No IP available — don't block (edge case)

    try {
      // Layer 1: Redis cache
      if (redis) {
        const cached = await redis.get(`${CACHE_PREFIX}${ip}`);
        if (cached === 'blocked') {
          logger.debug('checkIpBlock: blocked (cache hit)', { ip: ip.slice(0, 8) + '***' });
          return res.status(403).json({ success: false, error: 'Forbidden' });
        }
        if (cached === 'allowed') {
          return next(); // Known-good IP, skip DB
        }
      }

      // Layer 2: DB check (cache miss)
      const block = await IpBlocklist.isBlocked(ip);

      // Cache the result
      if (redis) {
        const cacheValue = block ? 'blocked' : 'allowed';
        await redis.set(`${CACHE_PREFIX}${ip}`, cacheValue, 'EX', CACHE_TTL).catch(() => {});
      }

      if (block) {
        logger.warn('checkIpBlock: IP blocked', {
          ip: ip.slice(0, 8) + '***',
          reason: block.reason,
          scope: block.scope,
        });
        return res.status(403).json({ success: false, error: 'Forbidden' });
      }

      next();
    } catch (err) {
      // Fail-open: if DB/Redis is down, don't block legitimate traffic
      logger.error('checkIpBlock: error checking IP block — fail-open', { error: err.message });
      next();
    }
  };
}

module.exports = checkIpBlock;
