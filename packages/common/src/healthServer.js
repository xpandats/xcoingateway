'use strict';

/**
 * @module packages/common/src/healthServer
 *
 * Minimal HTTP health server for background worker services.
 * These services don't run Express — they're pure Redis queue consumers.
 * This adds a lightweight health endpoint without pulling in the full Express stack.
 *
 * Usage:
 *   const { startHealthServer } = require('@xcg/common/src/healthServer');
 *   startHealthServer({ port: 3091, service: 'matching-engine', mongoose, redis });
 *
 * Routes:
 *   GET /health       — liveness (always 200 if process is alive)
 *   GET /health/ready — readiness (checks DB + Redis, returns 503 if down)
 */

const http = require('http');

const startTime = Date.now();

/**
 * Start a minimal health check HTTP server.
 *
 * @param {object} opts
 * @param {number}  opts.port     - Port to listen on
 * @param {string}  opts.service  - Service name
 * @param {object}  [opts.mongoose] - Mongoose instance
 * @param {object}  [opts.redis]    - IORedis instance
 * @param {object}  opts.logger
 */
function startHealthServer({ port, service, mongoose, redis, logger }) {
  const server = http.createServer(async (req, res) => {
    // Only handle health routes — ignore everything else
    if (!req.url.startsWith('/health')) {
      res.writeHead(404);
      res.end('Not Found');
      return;
    }

    const isReady = req.url === '/health/ready';
    let dbOk      = true;
    let redisOk   = true;

    if (isReady) {
      // DB check
      if (mongoose) {
        dbOk = mongoose.connection.readyState === 1;
      }

      // Redis check
      if (redis) {
        try {
          await redis.ping();
        } catch {
          redisOk = false;
        }
      }
    }

    const allOk   = dbOk && redisOk;
    const status  = isReady ? (allOk ? 'ready' : 'degraded') : 'alive';
    const code    = (isReady && !allOk) ? 503 : 200;
    const uptime  = Math.floor((Date.now() - startTime) / 1000);

    const body = JSON.stringify({
      service,
      status,
      uptime: `${uptime}s`,
      timestamp: new Date().toISOString(),
      ...(isReady && {
        checks: {
          database: dbOk   ? 'ok' : 'error',
          redis:    redisOk ? 'ok' : 'error',
        },
      }),
    });

    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(body);
  });

  server.listen(port, '0.0.0.0', () => {
    logger.info(`${service}: health server running on port ${port}`);
  });

  server.on('error', (err) => {
    logger.error(`${service}: health server error`, { error: err.message });
  });

  return server;
}

module.exports = { startHealthServer };
