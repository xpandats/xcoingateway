'use strict';

/**
 * @module packages/common/src/redisFactory
 *
 * Redis Connection Factory — Sentinel + Cluster Support.
 *
 * WHY THIS EXISTS (Gap 5 fix):
 *   A single Redis node is a single point of failure. If Redis goes down:
 *     - Nonce deduplication fails → replay attacks possible
 *     - Distributed withdrawal locks fail → double-spend risk
 *     - BullMQ queues fail → all async job processing stops
 *     - Rate limiting fails → unlimited throughput from any IP
 *     - Caching fails → every request hits DB
 *
 *   Redis Sentinel provides automatic failover: if the primary fails, a Sentinel
 *   replica is promoted within seconds. IORedis has native Sentinel support.
 *   This factory builds the correct IORedis client based on ENV config.
 *
 * MODES (set via REDIS_MODE env):
 *   standalone (default) — single Redis node (dev/test/simple prod)
 *   sentinel             — Redis Sentinel (recommended for production)
 *   cluster              — Redis Cluster (for very high throughput)
 *
 * SENTINEL SETUP (Docker Compose example in comments below):
 *   Set these ENV vars:
 *     REDIS_MODE=sentinel
 *     REDIS_SENTINEL_HOSTS=sentinel1:26379,sentinel2:26379,sentinel3:26379
 *     REDIS_SENTINEL_NAME=mymaster
 *     REDIS_PASSWORD=yourpassword (optional)
 *
 * CLUSTER SETUP:
 *     REDIS_MODE=cluster
 *     REDIS_CLUSTER_NODES=node1:7000,node2:7001,node3:7002
 *
 * STANDALONE (current default, keeps backward compat):
 *     REDIS_URL=redis://localhost:6379
 *
 * USAGE:
 *   const { createRedisClient } = require('@xcg/common/src/redisFactory');
 *   const redis = createRedisClient({ logger });
 *   // Returns IORedis instance — same API regardless of mode
 *
 * NOTE ON BULLMQ:
 *   BullMQ requires its own connection (cannot share with the app Redis instance
 *   in some configurations). The queue package creates its own connections using
 *   the raw host/port options. Sentinel-aware queue connections require BullMQ
 *   Enterprise or using the Sentinel-aware connection object. This is documented
 *   below.
 */

const IORedis  = require('ioredis');

const REDIS_MODE = process.env.REDIS_MODE || 'standalone';

/**
 * Create an IORedis client configured for the current mode.
 *
 * @param {object} [opts]
 * @param {object} [opts.logger]
 * @param {object} [opts.extraOptions] - additional IORedis constructor options
 * @returns {IORedis.Redis | IORedis.Cluster}
 */
function createRedisClient({ logger, extraOptions = {} } = {}) {
  const log = logger || console;

  switch (REDIS_MODE) {

    // ── Sentinel Mode ────────────────────────────────────────────────────────
    case 'sentinel': {
      // Parse sentinel hosts: "sentinel1:26379,sentinel2:26379,sentinel3:26379"
      const sentinelHostsRaw = process.env.REDIS_SENTINEL_HOSTS || 'localhost:26379';
      const sentinels = sentinelHostsRaw.split(',').map((h) => {
        const [host, port] = h.trim().split(':');
        return { host, port: Number(port) || 26379 };
      });

      const masterName = process.env.REDIS_SENTINEL_NAME || 'mymaster';
      const password   = process.env.REDIS_PASSWORD       || undefined;

      log.info?.(`Redis: connecting via Sentinel (master: ${masterName}, sentinels: ${sentinelHostsRaw})`);

      const client = new IORedis({
        sentinels,
        name:     masterName,
        password,
        // IORedis retries after Sentinel failover automatically
        sentinelRetryStrategy: (times) => Math.min(times * 100, 3000),
        retryStrategy:         (times) => Math.min(times * 150, 5000),
        maxRetriesPerRequest:  null, // Required for BullMQ-compatible connections
        enableOfflineQueue:    true, // Queue commands during failover (not for critical paths)
        ...extraOptions,
      });

      client.on('error', (err) => log.error?.('Redis Sentinel error', { error: err.message }));
      client.on('+switch-master', (master, from, to) => {
        log.warn?.('Redis Sentinel: master switched', { master, from: `${from.ip}:${from.port}`, to: `${to.ip}:${to.port}` });
      });

      return client;
    }

    // ── Cluster Mode ──────────────────────────────────────────────────────────
    case 'cluster': {
      const clusterNodesRaw = process.env.REDIS_CLUSTER_NODES || 'localhost:7000';
      const nodes = clusterNodesRaw.split(',').map((n) => {
        const [host, port] = n.trim().split(':');
        return { host, port: Number(port) || 7000 };
      });

      const password = process.env.REDIS_PASSWORD || undefined;

      log.info?.(`Redis: connecting via Cluster (nodes: ${clusterNodesRaw})`);

      const client = new IORedis.Cluster(nodes, {
        redisOptions: {
          password,
          maxRetriesPerRequest: null,
          ...extraOptions,
        },
        clusterRetryStrategy: (times) => Math.min(times * 100, 3000),
        enableOfflineQueue:    true,
      });

      client.on('error', (err) => log.error?.('Redis Cluster error', { error: err.message }));
      return client;
    }

    // ── Standalone Mode (default) ─────────────────────────────────────────────
    case 'standalone':
    default: {
      const url      = process.env.REDIS_URL || 'redis://localhost:6379';
      const password = process.env.REDIS_PASSWORD || undefined;

      log.info?.(`Redis: connecting standalone (${url})`);

      const client = new IORedis(url, {
        password,
        maxRetriesPerRequest:  null,
        retryStrategy:         (times) => Math.min(times * 150, 5000),
        enableOfflineQueue:    true,
        lazyConnect:           false,
        ...extraOptions,
      });

      client.on('error', (err) => log.error?.('Redis error', { error: err.message }));
      return client;
    }
  }
}

/**
 * Create a separate Redis connection for BullMQ workers/queues.
 *
 * BullMQ MAY require maxRetriesPerRequest: null and does not support
 * lazy connections well. This creates a dedicated connection with correct
 * settings so app Redis and queue Redis don't interfere.
 *
 * NOTE: Sentinel-aware BullMQ connections require passing the full IORedis
 * Sentinel config to BullMQ's `connection` option (BullMQ v4+):
 *   new Worker(queueName, processor, { connection: createRedisClient() });
 *
 * The existing createConsumer/createPublisher in @xcg/queue must be updated
 * to accept an IORedis instance (not just host/port) to support Sentinel.
 * For now this returns a standalone client — Sentinel upgrade tracked in backlog.
 */
function createBullMQConnection() {
  return createRedisClient({ extraOptions: { maxRetriesPerRequest: null, lazyConnect: false } });
}

module.exports = { createRedisClient, createBullMQConnection };

/*
 * ─────────────────────────────────────────────────────────────────────────────
 * DOCKER COMPOSE SENTINEL EXAMPLE (docker-compose.sentinel.yml)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * version: '3.8'
 * services:
 *   redis-master:
 *     image: redis:7-alpine
 *     command: redis-server --requirepass ${REDIS_PASSWORD}
 *     ports: ["6379:6379"]
 *
 *   redis-replica:
 *     image: redis:7-alpine
 *     command: >
 *       redis-server --requirepass ${REDIS_PASSWORD}
 *       --replicaof redis-master 6379
 *       --masterauth ${REDIS_PASSWORD}
 *     depends_on: [redis-master]
 *
 *   sentinel1: &sentinel
 *     image: redis:7-alpine
 *     command: >
 *       redis-sentinel /etc/redis/sentinel.conf
 *     volumes: [./config/sentinel.conf:/etc/redis/sentinel.conf]
 *     depends_on: [redis-master]
 *     ports: ["26379:26379"]
 *
 *   sentinel2:
 *     <<: *sentinel
 *     ports: ["26380:26379"]
 *
 *   sentinel3:
 *     <<: *sentinel
 *     ports: ["26381:26379"]
 *
 * # sentinel.conf:
 * # sentinel monitor mymaster redis-master 6379 2
 * # sentinel auth-pass mymaster ${REDIS_PASSWORD}
 * # sentinel down-after-milliseconds mymaster 5000
 * # sentinel failover-timeout mymaster 10000
 * # sentinel parallel-syncs mymaster 1
 * ─────────────────────────────────────────────────────────────────────────────
 */
