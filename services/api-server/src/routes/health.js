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
 * Load balancers use this to know if the process should be restarted.
 */
router.get('/', (req, res) => {
  res.json(response.success({
    service: 'api-server',
    status: 'alive',
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    pid: process.pid,
  }));
});

/**
 * Readiness probe — are all dependencies ready to serve traffic?
 * Load balancers use this to know if the instance should receive traffic.
 * Returns 503 if any critical dependency is DOWN.
 */
router.get('/ready', async (req, res) => {
  const memory = process.memoryUsage();
  const dbStatus = isDBConnected() ? 'connected' : 'disconnected';
  const dbReadyState = mongoose.connection.readyState;

  // Map Mongoose readyState to human-readable string
  const dbStateMap = { 0: 'disconnected', 1: 'connected', 2: 'connecting', 3: 'disconnecting' };

  const checks = {
    database: {
      status: dbStatus,
      readyState: dbStateMap[dbReadyState] || 'unknown',
      healthy: dbStatus === 'connected',
    },
    memory: {
      heapUsedMB: Math.round(memory.heapUsed / 1024 / 1024),
      heapTotalMB: Math.round(memory.heapTotal / 1024 / 1024),
      rssMB: Math.round(memory.rss / 1024 / 1024),
      healthy: memory.heapUsed < memory.heapTotal * 0.9, // Alert if >90% heap used
    },
    process: {
      uptimeSeconds: Math.floor(process.uptime()),
      nodeVersion: process.version,
      healthy: true,
    },
  };

  const allHealthy = Object.values(checks).every((c) => c.healthy);
  const statusCode = allHealthy ? 200 : 503;

  res.status(statusCode).json(response.success({
    service: 'api-server',
    status: allHealthy ? 'ready' : 'degraded',
    timestamp: new Date().toISOString(),
    checks,
  }));
});

module.exports = router;
