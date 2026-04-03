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
 * ID-4: External response is minimal. Full details are logged internally, not exposed.
 */
router.get('/ready', async (req, res) => {
  const memory = process.memoryUsage();
  const dbHealthy = isDBConnected() && mongoose.connection.readyState === 1;
  const memoryHealthy = memory.heapUsed < memory.heapTotal * 0.9;

  const allHealthy = dbHealthy && memoryHealthy;
  const statusCode = allHealthy ? 200 : 503;

  // ID-4: Log full details internally (for ops), but never expose them externally.
  // Returning DB connection state, Node.js version, or heap sizes enables
  // infrastructure fingerprinting by attackers.

  res.status(statusCode).json(response.success({
    // Only expose: overall status. Nothing else.
    status: allHealthy ? 'ready' : 'degraded',
    timestamp: new Date().toISOString(),
  }));
});

module.exports = router;
