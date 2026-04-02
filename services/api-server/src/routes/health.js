'use strict';

const express = require('express');
const router = express.Router();
const { isDBConnected } = require('@xcg/database');

/**
 * Health check endpoint (internal only — not exposed publicly).
 */
router.get('/', (req, res) => {
  const health = {
    status: 'ok',
    service: 'api-server',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    checks: {
      database: isDBConnected() ? 'connected' : 'disconnected',
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + 'MB',
      },
    },
  };

  const statusCode = isDBConnected() ? 200 : 503;
  res.status(statusCode).json(health);
});

module.exports = router;
