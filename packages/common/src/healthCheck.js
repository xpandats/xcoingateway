'use strict';

/**
 * @module packages/common/src/healthCheck
 *
 * Shared health check handler factory.
 * Every service exposes GET /health with:
 *   - DB connected
 *   - Redis connected
 *   - Service-specific checks (via opts.checks)
 *   - Uptime
 *   - Memory stats
 */

const os = require('os');

/**
 * Create an Express health check handler for a service.
 *
 * @param {object} opts
 * @param {string}   opts.service      - Service name
 * @param {object}   [opts.mongoose]   - Mongoose instance (for DB state check)
 * @param {object}   [opts.redis]      - IORedis instance (for Redis ping)
 * @param {Function[]} [opts.checks]   - Array of async () => { name, status, detail } functions
 */
function createHealthHandler(opts = {}) {
  const { service = 'unknown', mongoose, redis, checks = [] } = opts;
  const startTime = Date.now();

  return async function healthHandler(req, res) {
    const results = {};
    let overallOk = true;

    // DB check
    if (mongoose) {
      const state = mongoose.connection.readyState;
      // 1 = connected, 2 = connecting, 3 = disconnecting, 0 = disconnected
      const dbOk = state === 1;
      results.database = { status: dbOk ? 'ok' : 'error', readyState: state };
      if (!dbOk) overallOk = false;
    }

    // Redis check
    if (redis) {
      try {
        await redis.ping();
        results.redis = { status: 'ok' };
      } catch (err) {
        results.redis = { status: 'error', error: err.message };
        overallOk = false;
      }
    }

    // Custom service checks
    for (const check of checks) {
      try {
        const result = await check();
        results[result.name] = { status: result.status, detail: result.detail || null };
        if (result.status !== 'ok') overallOk = false;
      } catch (err) {
        overallOk = false;
      }
    }

    const uptime    = Math.floor((Date.now() - startTime) / 1000);
    const memUsage  = process.memoryUsage();

    const body = {
      service,
      status:  overallOk ? 'ok' : 'degraded',
      uptime:  `${uptime}s`,
      checks:  results,
      system: {
        memRssMB:    (memUsage.rss / 1024 / 1024).toFixed(1),
        memHeapMB:   (memUsage.heapUsed / 1024 / 1024).toFixed(1),
        cpuCount:    os.cpus().length,
        nodeVersion: process.version,
      },
      timestamp: new Date().toISOString(),
    };

    // Use 200 even when degraded — let load balancer decide; 503 for critical failures
    const httpStatus = overallOk ? 200 : 503;
    res.status(httpStatus).json(body);
  };
}

module.exports = { createHealthHandler };
