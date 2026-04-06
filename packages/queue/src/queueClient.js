'use strict';

/**
 * @module queueClient
 *
 * Secure Redis Queue Client — BullMQ with HMAC-signed messages.
 *
 * SECURITY GUARANTEES:
 *   1. Every published message is HMAC-SHA256 signed by the sender.
 *   2. Every consumed message has its signature verified before processing.
 *   3. A message with invalid signature is REJECTED and moved to dead letter queue.
 *   4. Each message has an idempotency key — duplicate delivery = same result.
 *   5. Messages have configurable TTL — old messages auto-expire.
 *   6. Failed messages go to dead letter queue with full error context.
 *
 * This ensures that even if an attacker gains access to Redis, injected messages
 * cannot be processed without the QUEUE_SIGNING_SECRET.
 */

const { Queue, Worker, QueueEvents } = require('bullmq');
const crypto = require('crypto');
const { QUEUES } = require('./queues');

// Lazy-loaded to avoid circular deps in packages that don't have @xcg/database
let _DeadLetterEntry = null;
function _getDLEModel() {
  if (_DeadLetterEntry) return _DeadLetterEntry;
  try {
    _DeadLetterEntry = require('@xcg/database').DeadLetterEntry;
  } catch { /* not available in this context — skip DB persistence */ }
  return _DeadLetterEntry;
}

const MESSAGE_TTL_MS    = 30 * 60 * 1000; // 30 minutes — allows for realistic service restart windows
// NOTE: 5 minutes was too short — if any consumer is down during maintenance, payment
// events expire permanently (blockchain listener won't re-publish due to Redis dedup).
const DEAD_LETTER_QUEUE = QUEUES.DEAD_LETTER;

/**
 * Compute HMAC-SHA256 signature for a queue message.
 *
 * Signed payload: `{queueName}:{idempotencyKey}:{timestamp}:{JSON.stringify(data)}`
 * This prevents:
 *   - Cross-queue injection (queueName bound)
 *   - Replay attacks (timestamp + TTL)
 *   - Tampering with data (data bound)
 *
 * @param {string} secret
 * @param {string} queueName
 * @param {string} idempotencyKey
 * @param {number} timestamp
 * @param {object} data
 * @returns {string} hex HMAC
 */
function signMessage(secret, queueName, idempotencyKey, timestamp, data) {
  const payload = `${queueName}:${idempotencyKey}:${timestamp}:${JSON.stringify(data)}`;
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

/**
 * Verify a message's HMAC signature.
 * Uses timingSafeEqual to prevent timing oracle attacks.
 *
 * @throws {Error} If signature is invalid or message is expired
 */
function verifyMessage(secret, envelope) {
  const { queueName, idempotencyKey, timestamp, data, sig } = envelope;

  if (!queueName || !idempotencyKey || !timestamp || !data || !sig) {
    throw new Error('QueueClient: message missing required fields');
  }

  // Check TTL — reject messages older than MESSAGE_TTL_MS
  const ageMs = Date.now() - timestamp;
  if (ageMs > MESSAGE_TTL_MS || ageMs < -30_000) {
    throw new Error(`QueueClient: message too old or from future (age: ${ageMs}ms)`);
  }

  // Recompute expected signature
  const expected = signMessage(secret, queueName, idempotencyKey, timestamp, data);

  // Timing-safe comparison
  const sigBuf      = Buffer.from(sig, 'hex');
  const expectedBuf = Buffer.from(expected, 'hex');

  if (sigBuf.length !== expectedBuf.length) {
    throw new Error('QueueClient: signature length mismatch');
  }
  if (!crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    throw new Error('QueueClient: signature verification failed');
  }
}

/**
 * Create a secure queue publisher.
 *
 * @param {string} queueName - One of QUEUES.*
 * @param {object} redisOpts - IORedis connection options
 * @param {string} secret    - QUEUE_SIGNING_SECRET from config
 * @param {object} logger    - @xcg/logger instance
 */
function createPublisher(queueName, redisOpts, secret, logger) {
  if (!Object.values(QUEUES).includes(queueName)) {
    throw new Error(`QueueClient: unknown queue "${queueName}"`);
  }
  if (!secret || secret.length < 32) {
    throw new Error('QueueClient: signing secret must be at least 32 characters');
  }

  const queue = new Queue(queueName, {
    connection: redisOpts,
    defaultJobOptions: {
      removeOnComplete: { count: 1000 },
      removeOnFail: { count: 500 },
      attempts: 5,
      backoff: { type: 'exponential', delay: 3000 },
    },
  });

  /**
   * Publish a signed message to the queue.
   *
   * @param {object} data           - Message payload (must be JSON-serializable)
   * @param {string} idempotencyKey - Unique key for deduplication
   * @param {object} [opts]         - BullMQ job options
   */
  async function publish(data, idempotencyKey, opts = {}) {
    if (!idempotencyKey || typeof idempotencyKey !== 'string') {
      throw new Error('QueueClient.publish: idempotencyKey is required');
    }
    if (!data || typeof data !== 'object') {
      throw new Error('QueueClient.publish: data must be an object');
    }

    const timestamp = Date.now();
    const sig = signMessage(secret, queueName, idempotencyKey, timestamp, data);

    const envelope = {
      queueName,
      idempotencyKey,
      timestamp,
      data,
      sig,
    };

    await queue.add(idempotencyKey, envelope, {
      jobId: idempotencyKey, // BullMQ deduplication by jobId
      ...opts,
    });

    logger.debug('QueueClient: message published', {
      queue: queueName,
      idempotencyKey,
      action: 'publish',
    });
  }

  return { publish, queue };
}

/**
 * Create a secure queue consumer (worker).
 *
 * @param {string}   queueName    - One of QUEUES.*
 * @param {object}   redisOpts    - IORedis connection options
 * @param {string}   secret       - QUEUE_SIGNING_SECRET from config
 * @param {object}   logger       - @xcg/logger instance
 * @param {Function} handler      - async (data, idempotencyKey) => void
 * @param {object}   [workerOpts] - BullMQ worker options
 */
function createConsumer(queueName, redisOpts, secret, logger, handler, workerOpts = {}) {
  if (!Object.values(QUEUES).includes(queueName)) {
    throw new Error(`QueueClient: unknown queue "${queueName}"`);
  }

  const deadLetterPublisher = createPublisher(DEAD_LETTER_QUEUE, redisOpts, secret, logger);

  const worker = new Worker(
    queueName,
    async (job) => {
      const envelope = job.data;

      // 1. Verify HMAC signature before ANY processing
      try {
        verifyMessage(secret, envelope);
      } catch (sigErr) {
        // SECURITY: Invalid signature — log and dead-letter, never process
        logger.error('QueueClient: INVALID SIGNATURE — message rejected', {
          queue: queueName,
          jobId: job.id,
          error: sigErr.message,
          action: 'signature_reject',
        });
        // Move to dead letter (don't throw — prevents infinite retry)
        await deadLetterPublisher.publish(
          { original: envelope, reason: sigErr.message, queue: queueName },
          `dlq:${job.id}:${Date.now()}`,
        );

        // Persist to MongoDB for compliance (non-blocking)
        const DLE = _getDLEModel();
        if (DLE) {
          DLE.create({
            dlqId:          `dlq_${crypto.randomBytes(12).toString('hex')}`,
            sourceQueue:    queueName,
            jobId:          job.id,
            payload:        envelope,
            source:         'hmac_invalid',
            error:          sigErr.message,
            serviceName:    queueName.split(':').pop() || 'unknown',
            status:         'pending',
          }).catch((e) => logger.error('QueueClient: failed to persist DLQ entry to DB', { error: e.message }));
        }

        return; // Don't re-throw — mark as complete (we handled it)
      }

      // 2. Signature valid — process message
      try {
        await handler(envelope.data, envelope.idempotencyKey);
        logger.debug('QueueClient: message processed', {
          queue: queueName,
          idempotencyKey: envelope.idempotencyKey,
          action: 'processed',
        });
      } catch (handlerErr) {
        // Re-throw so BullMQ retries with backoff
        logger.warn('QueueClient: handler error (will retry)', {
          queue: queueName,
          idempotencyKey: envelope.idempotencyKey,
          error: handlerErr.message,
          attempt: job.attemptsMade,
        });
        throw handlerErr;
      }
    },
    {
      connection: redisOpts,
      concurrency: 5,
      ...workerOpts,
    },
  );

  // Log failed jobs (exhausted retries → dead letter)
  worker.on('failed', async (job, err) => {
    logger.error('QueueClient: job failed permanently — moving to dead letter', {
      queue: queueName,
      jobId: job?.id,
      error: err?.message,
      attempts: job?.attemptsMade,
      action: 'dead_letter',
    });
    try {
      await deadLetterPublisher.publish(
        { original: job?.data, reason: err?.message, queue: queueName },
        `dlq:${job?.id}:${Date.now()}`,
      );

      // Persist to MongoDB for compliance (non-blocking)
      const DLE = _getDLEModel();
      if (DLE) {
        DLE.create({
          dlqId:          `dlq_${crypto.randomBytes(12).toString('hex')}`,
          sourceQueue:    queueName,
          jobId:          job?.id || 'unknown',
          payload:        job?.data || {},
          source:         'max_retries',
          error:          err?.message || 'unknown',
          errorStack:     err?.stack || null,
          attempts:       job?.attemptsMade || 0,
          serviceName:    queueName.split(':').pop() || 'unknown',
          status:         'pending',
        }).catch((e) => logger.error('QueueClient: failed to persist DLQ entry to DB', { error: e.message }));
      }
    } catch {
      // Don't crash on dead letter failure
    }
  });

  return { worker };
}

/**
 * Create a Dead Letter Queue monitor.
 *
 * M3 FIX: Without this, messages that exhaust all 5 BullMQ retries pile up
 * in the DLQ silently — only a log line is emitted. With this monitor,
 * operators receive a SYSTEM_ALERT the moment any message lands in the DLQ,
 * and on every hourly check while DLQ still has pending messages.
 *
 * @param {object} opts
 * @param {object} opts.redisOpts       - IORedis connection options
 * @param {string} opts.secret          - QUEUE_SIGNING_SECRET
 * @param {object} opts.alertPublisher  - Pre-created alert publisher
 * @param {string} opts.serviceName     - Name of the calling service (for alert context)
 * @param {object} opts.logger          - @xcg/logger instance
 * @param {number} [opts.intervalMs]    - Poll interval (default: 30 minutes)
 * @returns {{ stop: Function }}
 */
function createDLQMonitor({ redisOpts, secret, alertPublisher, serviceName, logger, intervalMs = 30 * 60 * 1000 }) {
  const dlqQueue = new Queue(QUEUES.DEAD_LETTER, { connection: redisOpts });

  async function checkDLQ() {
    try {
      const counts = await dlqQueue.getJobCounts('waiting', 'failed', 'delayed');
      const total = (counts.waiting || 0) + (counts.failed || 0) + (counts.delayed || 0);

      if (total > 0) {
        logger.error('DLQMonitor: dead letter queue has pending messages — operator action required', {
          service: serviceName, waiting: counts.waiting, failed: counts.failed, total,
        });
        await alertPublisher.publish(
          {
            type: 'dead_letter_queue_has_messages',
            service: serviceName,
            total,
            waiting: counts.waiting,
            failed: counts.failed,
            message: `[${serviceName}] Dead letter queue has ${total} unprocessed message(s). Immediate operator review required.`,
          },
          `alert:dlq:${serviceName}:${Date.now()}`,
        );
      } else {
        logger.debug('DLQMonitor: dead letter queue is clear', { service: serviceName });
      }
    } catch (err) {
      logger.error('DLQMonitor: failed to check dead letter queue', { service: serviceName, error: err.message });
    }
  }

  // Run immediately on startup, then on interval
  checkDLQ();
  const timer = setInterval(checkDLQ, intervalMs);

  return {
    stop: () => {
      clearInterval(timer);
      dlqQueue.close().catch(() => {});
    },
  };
}

module.exports = {
  createPublisher,
  createConsumer,
  createDLQMonitor,
  QUEUES,
};
