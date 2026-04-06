'use strict';

/**
 * @module models/ServiceHealthSnapshot
 *
 * Service Health Snapshot — Periodic health check results for monitoring.
 *
 * WHY THIS EXISTS (from Description.txt):
 *   "Every service exposes internal health check:
 *    - Database connected?
 *    - Redis connected?
 *    - TronGrid reachable?
 *    - Last block scanned (stale detection)?
 *    - Queue depth (processing stuck)?
 *    - Memory/CPU within limits?"
 *
 *   Each service has a /internal/health/ready endpoint, but:
 *     - Health checks are point-in-time — no history
 *     - "When did the blockchain listener go unhealthy?" → unknown
 *     - "Is service X degraded over the last hour?" → no time series
 *     - Dashboard needs historical health data, not just current status
 *
 * TTL: Auto-deletes after 7 days to prevent unbounded growth.
 */

const mongoose = require('mongoose');

const HEALTH_STATUS = Object.freeze({
  HEALTHY:   'healthy',
  DEGRADED:  'degraded',    // Partially functional (e.g., one Redis sentinel down)
  UNHEALTHY: 'unhealthy',   // Critical failure
});

const serviceHealthSnapshotSchema = new mongoose.Schema({
  // Which service
  serviceName: { type: String, required: true, index: true },
  instanceId:  { type: String, default: null },  // For multi-instance services

  // Overall status
  status: {
    type: String,
    enum: Object.values(HEALTH_STATUS),
    required: true,
    index: true,
  },

  // Dependencies status
  dependencies: {
    mongodb:  { type: String, enum: ['up', 'down', 'degraded', 'n/a'], default: 'n/a' },
    redis:    { type: String, enum: ['up', 'down', 'degraded', 'n/a'], default: 'n/a' },
    trongrid: { type: String, enum: ['up', 'down', 'degraded', 'n/a'], default: 'n/a' },
  },

  // Queue health
  queues: {
    pendingJobs:    { type: Number, default: 0 },
    activeJobs:     { type: Number, default: 0 },
    failedJobs:     { type: Number, default: 0 },
    delayedJobs:    { type: Number, default: 0 },
    dlqDepth:       { type: Number, default: 0 },   // Dead letter queue depth
  },

  // Blockchain listener specific
  blockchain: {
    lastScannedBlock: { type: Number, default: null },
    blockAge:         { type: Number, default: null },    // Seconds since last block
    isStale:          { type: Boolean, default: false },   // True if block age > 30s
    activeProvider:   { type: String, default: null },     // 'trongrid' or 'tron_rpc'
  },

  // System resources
  system: {
    memoryUsedMb:    { type: Number, default: null },
    memoryTotalMb:   { type: Number, default: null },
    memoryPercent:   { type: Number, default: null },
    cpuPercent:      { type: Number, default: null },
    uptimeSeconds:   { type: Number, default: null },
    eventLoopLagMs:  { type: Number, default: null },
  },

  // Circuit breaker states
  circuitBreakers: {
    mongodb:  { type: String, enum: ['closed', 'open', 'half_open', 'n/a'], default: 'n/a' },
    trongrid: { type: String, enum: ['closed', 'open', 'half_open', 'n/a'], default: 'n/a' },
  },

  // Response time of health check itself
  checkDurationMs: { type: Number, default: null },
}, {
  timestamps: true,
  collection: 'service_health_snapshots',
  strict: true,
});

// TTL: auto-delete snapshots after 7 days
serviceHealthSnapshotSchema.index({ createdAt: 1 }, { expireAfterSeconds: 7 * 24 * 60 * 60 });

// Performance indexes
serviceHealthSnapshotSchema.index({ serviceName: 1, createdAt: -1 });
serviceHealthSnapshotSchema.index({ status: 1, createdAt: -1 });
serviceHealthSnapshotSchema.index({ 'blockchain.isStale': 1, createdAt: -1 });

module.exports = mongoose.model('ServiceHealthSnapshot', serviceHealthSnapshotSchema);
module.exports.HEALTH_STATUS = HEALTH_STATUS;
