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
 * Rate limiting: MAX 10 signing operations per minute.
 *
 * SECURITY RULES (NON-NEGOTIABLE):
 *   - Private key exists in plaintext for MINIMUM possible time
 *   - Buffer.fill(0) called on key buffer IMMEDIATELY after signing
 *   - No HTTP server, no external connections except Redis and TronGrid
 *   - Only the Withdrawal Engine's HMAC-signed requests are processed
 *   - Every signing operation logged to audit trail
 */

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env.local') });

const { config, validateConfig }    = require('../../api-server/src/config');
const { connectDB }                 = require('@xcg/database');
const { createLogger }              = require('@xcg/logger');
const { createConsumer, createPublisher, QUEUES } = require('@xcg/queue');
const IORedis                       = require('ioredis');
const Signer                        = require('./signer');

const logger = createLogger('signing-service');

// ── Rate Limiter (in-memory, sufficient for this isolated process) ────────────
const RATE_LIMIT_MAX_PER_MINUTE = 10;
let signingCountThisMinute = 0;
let rateLimitWindowStart   = Date.now();

function checkRateLimit() {
  const now = Date.now();
  if (now - rateLimitWindowStart > 60_000) {
    signingCountThisMinute = 0;
    rateLimitWindowStart   = now;
  }
  if (signingCountThisMinute >= RATE_LIMIT_MAX_PER_MINUTE) {
    throw new Error(`SigningService: rate limit exceeded (${RATE_LIMIT_MAX_PER_MINUTE} ops/min)`);
  }
  signingCountThisMinute++;
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

  // 3. Connect to Redis (queue only)
  const redis = new IORedis(config.redis.url, { maxRetriesPerRequest: null });
  redis.on('error', (err) => {
    logger.error('SigningService: Redis error', { error: err.message });
  });

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
      // Rate limit check
      checkRateLimit();

      logger.info('SigningService: signing request received', {
        requestId: data.requestId,
        walletId:  data.walletId,
        toAddress: data.toAddress,
        amount:    data.amount,
      });

      // Sign the transaction (key is zeroed after this call)
      const result = await signer.sign(data);

      // Return result via signing:complete queue
      await completePublisher.publish(
        {
          requestId: data.requestId,
          txHash:    result.txHash,
          success:   true,
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

  // 7. Graceful shutdown
  async function shutdown(signal) {
    logger.info(`SigningService: received ${signal}`);
    await worker.close();
    await redis.quit();
    process.exit(0);
  }

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));

  process.on('uncaughtException', (err) => {
    logger.error('SigningService: uncaught exception', { error: err.message });
    process.exit(1);
  });
  process.on('unhandledRejection', (reason) => {
    logger.error('SigningService: unhandled rejection', { reason: String(reason) });
    process.exit(1);
  });

  logger.info('SigningService: running — waiting for signing requests');

  // SECURITY: After startup, delete master key from process.env
  // It's already in config.encryption.masterKey — no need in env anymore
  delete process.env.MASTER_ENCRYPTION_KEY;
}

main().catch((err) => {
  console.error('SigningService: fatal startup error:', err.message);
  process.exit(1);
});
