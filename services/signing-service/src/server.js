'use strict';

/**
 * @module signing-service/server
 *
 * Signing Service — Zone 3 (Maximum Isolation).
 *
 * ╔══════════════════════════════════════════════════════════════╗
 * ║  THIS SERVICE HAS NO HTTP ENDPOINT.                         ║
 * ║  It listens ONLY on an internal Redis queue.                ║
 * ║  Private keys NEVER leave this process.                     ║
 * ║  This service MUST run as a separate OS user.               ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Architecture:
 *   Withdrawal Engine ──→ [signing:request] ──→ THIS SERVICE
 *   THIS SERVICE ──→ [signing:complete] ──→ Withdrawal Engine
 *
 * Every signing request:
 *   1. HMAC signature verified (queue-level)
 *   2. Request schema validated
 *   3. Encrypted private key fetched from DB
 *   4. Key decrypted → sign transaction → key ZEROED immediately
 *   5. Signed TX broadcast to Tron network
 *   6. TX hash returned via queue
 *
 * ════════════════════════════════════════════════════════
 * GAP 2: HORIZONTAL SCALING STRATEGY (documented here)
 * ════════════════════════════════════════════════════════
 * The signing service CAN scale horizontally with ZERO code changes.
 *
 * HOW: BullMQ guarantees each job is consumed by exactly ONE worker.
 *   Worker 1 takes job A, Worker 2 takes job B — no double-signing possible.
 *   This is BullMQ's core guarantee: RPOPLPUSH-based atomic job acquisition.
 *
 * WHAT SCALES:
 *   - Add more signing-service replicas (docker --scale, k8s replicas)
 *   - All workers consume from the same `signing:request` BullMQ queue
 *   - concurrency: 1 is per-worker (intentional — never sign two txs in parallel
 *     within one process to keep key memory exposure minimal)
 *   - Total throughput = N workers × 1 concurrent signing = N signings in parallel
 *   - Default cap: 10 signings/min (RATE_LIMIT_MAX_PER_MINUTE) — Redis-backed
 *     so N workers collectively respect the cap, not per-instance
 *
 * WHAT DOESN'T SCALE:
 *   - The master key (MASTER_ENCRYPTION_KEY) must be identical across all instances.
 *     This is already the case — it comes from ENV.
 *   - Key access visibility: with N instances you have N plaintext key windows.
 *     Mitigated by concurrency:1 and Buffer.fill(0) immediately after signing.
 *
 * VERDICT: Run 2-3 signing instances for HA (not throughput). BullMQ handles
 * the distribution. Leader election is NOT needed here (unlike blockchain-listener)
 * because BullMQ consumers are naturally distributed — one job = one worker.
 *
 * ════════════════════════════════════════════════════════
 * GAP 3: SESSION AFFINITY FOR WEBSOCKETS (architectural note)
 * ════════════════════════════════════════════════════════
 * When WebSocket real-time updates are added (merchant dashboard live updates,
 * admin monitoring), the current stateless architecture will need one of:
 *
 * Option A — Sticky Sessions (simpler, works with Nginx):
 *   Nginx ip_hash or cookie-based routing keeps each client on the same API server.
 *   Limitation: doesn’t survive server restarts. Works for MVP.
 *
 * Option B — Redis Pub/Sub broadcast (recommended, used by Socket.IO):
 *   Each API server subscribes to Redis channels. Events published to Redis
 *   are broadcast to ALL connected WebSocket clients on ALL servers.
 *   Implementation: socket.io + socket.io-redis adapter.
 *   This is the standard approach for horizontally scaled Socket.IO.
 *
 * Current state: No WebSocket endpoints exist. This is architecture-ready
 * (Redis is already in the dependency graph). Tracked for Phase 5+.
 */

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env.local') });

const { config, validateConfig }    = require('../../api-server/src/config');
const { connectDB }                 = require('@xcg/database');
const { createLogger }              = require('@xcg/logger');
const { createConsumer, createPublisher, QUEUES } = require('@xcg/queue');
const { createRedisClient }         = require('@xcg/common/src/redisFactory');
const { startHealthServer }         = require('@xcg/common/src/healthServer');
const { registerShutdown, runMain } = require('@xcg/common/src/shutdown');
const Signer                        = require('./signer');



const logger = createLogger('signing-service');

// ── Rate Limiter — Redis-backed so multiple instances respect a shared cap ─────────────
// Gap 2 fix: The original in-memory limiter allowed each replica to fire
// RATE_LIMIT_MAX_PER_MINUTE independently, so 3 instances = 30 signings/min.
// A Redis counter ensures the cap is enforced GLOBALLY across all instances.
// Key: xcg:sign:rate:{windowStart} (resets every minute)
const RATE_LIMIT_MAX_PER_MINUTE = parseInt(process.env.SIGNING_RATE_LIMIT, 10) || 10;

async function checkRateLimit(redis) {
  const windowKey = `xcg:sign:rate:${Math.floor(Date.now() / 60_000)}`;
  const count     = await redis.incr(windowKey);
  if (count === 1) {
    // First in window: set TTL to 70s (slightly over 1 min to handle clock skew)
    await redis.expire(windowKey, 70);
  }
  if (count > RATE_LIMIT_MAX_PER_MINUTE) {
    throw new Error(`SigningService: global rate limit exceeded (${count}/${RATE_LIMIT_MAX_PER_MINUTE} ops/min across all instances)`);
  }
}

async function main() {
  logger.info('SigningService: starting up (Zone 3)');

  // 1. Validate config
  try {
    validateConfig();
  } catch (err) {
    logger.error('SigningService: config validation failed', { error: err.message });
    process.exit(1);
  }

  // 2. Connect to MongoDB (read-only for key retrieval)
  await connectDB(config.db.uri, logger);

  // 3. Connect to Redis (queue + rate limit counter)
  // Gap 5: Sentinel/Cluster-aware via REDIS_MODE env
  const redis = createRedisClient({ logger, extraOptions: { maxRetriesPerRequest: null } });
  redis.on('error', (err) => {
    logger.error('SigningService: Redis error', { error: err.message });
  });

  // 3b. Health server (internal only — port 3097)
  // Was missing: signing-service was the only service without a /health/ready endpoint.
  // Load balancer could not detect if this instance was degraded.
  const mongoose = require('mongoose'); // already connected via connectDB above
  startHealthServer({ port: 3097, service: 'signing-service', mongoose, redis, logger });



  // 4. Initialise signer
  const signer = new Signer({
    network:  config.tron.network,
    apiKey:   config.tron.apiKey,
    masterKey:config.encryption.masterKey,
    logger,
  });

  const redisOpts = {
    host: new URL(config.redis.url).hostname,
    port: Number(new URL(config.redis.url).port) || 6379,
  };

  // 5. Publisher for signing:complete responses
  const completePublisher = createPublisher(
    QUEUES.SIGNING_COMPLETE,
    redisOpts,
    config.queue.signingSecret,
    logger,
  );

  // 6. Consumer for signing:request queue
  const { worker } = createConsumer(
    QUEUES.SIGNING_REQUEST,
    redisOpts,
    config.queue.signingSecret,
    logger,
    async (data, idempotencyKey) => {
      // Rate limit check — Redis-backed, global across all instances (Gap 2 fix)
      await checkRateLimit(redis);


      logger.info('SigningService: signing request received', {
        requestId: data.requestId,
        walletId:  data.walletId,
        toAddress: data.toAddress,
        amount:    data.amount,
      });

      // Sign the transaction (key is zeroed after this call)
      const result = await signer.sign(data);

      // Return result via signing:complete queue
      // CRITICAL: withdrawalId MUST be included so the withdrawal engine can
      // find and update the withdrawal record status from 'signing' → 'broadcast'.
      // Without it, Withdrawal.findOneAndUpdate({ _id: undefined }) never matches.
      await completePublisher.publish(
        {
          requestId:    data.requestId,
          withdrawalId: data.withdrawalId, // ← required by withdrawal engine consumer
          txHash:       result.txHash,
          success:      true,
        },
        `complete:${data.requestId}`,
      );

      logger.info('SigningService: signing complete', {
        requestId: data.requestId,
        txHash:    result.txHash,
      });
    },
    { concurrency: 1 }, // SECURITY: Process one signing at a time, never parallel
  );

  registerShutdown({
    logger,
    service: 'signing-service',
    cleanup: async () => {
      await worker.close();
      await redis.quit();
    },
  });

  logger.info('SigningService: running — waiting for signing requests');

  // SECURITY: After startup, delete master key from process.env
  // It's already in config.encryption.masterKey — no need in env anymore
  delete process.env.MASTER_ENCRYPTION_KEY;
}

runMain(main, { logger, service: 'signing-service' });

