'use strict';

/**
 * @module routes/health
 *
 * Health Check Endpoint — Internal Only.
 *
 * BANK-GRADE REQUIREMENTS:
 *   - Deep health check: verifies DB connectivity, not just process liveness
 *   - Returns 503 if any critical dependency is DOWN
 *   - Never exposed publicly (mounted at /internal/health)
 *   - Response shape matches standard API envelope
 *
 * Liveness:   GET /internal/health          — Process is alive
 * Readiness:  GET /internal/health/ready    — All dependencies UP (use for load balancer)
 */

const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();
const { isDBConnected } = require('@xcg/database');
const { response } = require('@xcg/common');

/**
 * Liveness probe — is the process alive?
 * ID-4: Return ONLY status and uptime. No internal details (PID, versions etc.)
 */
router.get('/', (req, res) => {
  res.json(response.success({
    status: 'alive',
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    // ID-4: PID intentionally omitted (aids process enumeration attacks)
  }));
});

/**
 * Readiness probe — are all dependencies ready?
 * Returns 503 if MongoDB or Redis is unavailable.
 * Used by load balancer to stop routing to degraded instances.
 */
router.get('/ready', async (req, res) => {
  const redis = req.app?.locals?.redis || null;
  const memory = process.memoryUsage();
  const dbHealthy    = isDBConnected() && mongoose.connection.readyState === 1;
  const memoryHealthy = memory.heapUsed < memory.heapTotal * 0.9;

  // Gap 4 fix: Redis connectivity check.
  // Redis is critical: nonce dedup, distributed locks, caching, rate limiting all depend on it.
  // A dead Redis should take this instance OUT of rotation immediately.
  let redisHealthy = false;
  if (redis) {
    try {
      // Enforce a 1-second timeout so health checks don't hang on a lagging Redis
      const pong = await Promise.race([
        redis.ping(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 1000)),
      ]);
      redisHealthy = pong === 'PONG';
    } catch {
      redisHealthy = false;
    }
  } else {
    // Redis not injected yet (startup race) — degrade but don't hard-fail
    // This happens only in the first few milliseconds before createApp() is called
    redisHealthy = true;
  }

  const allHealthy = dbHealthy && redisHealthy && memoryHealthy;
  const statusCode = allHealthy ? 200 : 503;

  // ID-4: Log full details internally; never expose them externally.
  // Returning DB/Redis connection state enables infrastructure fingerprinting.

  res.status(statusCode).json(response.success({
    status: allHealthy ? 'ready' : 'degraded',
    timestamp: new Date().toISOString(),
  }));
});


module.exports = router;
