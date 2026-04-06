'use strict';

/**
 * @module blockchain-listener/leaderElection
 *
 * Distributed Leader Election for the Blockchain Listener.
 *
 * WHY THIS EXISTS:
 *   The blockchain listener runs a TronGrid polling loop. If two instances run
 *   simultaneously (e.g., during a rolling deploy, k8s replicas, or PM2 cluster
 *   mode), both will poll the same blocks and publish duplicate TRANSACTION_DETECTED
 *   events. The matching engine would then match the same payment twice, crediting
 *   the merchant double.
 *
 *   Deduplication in the matching engine (Redis seen-set) prevents double matching,
 *   but a cleaner and more efficient fix is ensuring only ONE listener polls at any
 *   given time.
 *
 * ALGORITHM: Redis SETNX Renewable Lock (leader lease)
 *   - Each instance tries to acquire key xcg:leader:blockchain-listener (SET NX PX ttlMs)
 *   - The winner becomes leader and starts polling
 *   - Leader renews every renewIntervalMs (must be < ttlMs to avoid gap)
 *   - On renewal failure → lose leadership → stop polling → retry acquisition
 *   - Non-leaders retry acquisition every retryIntervalMs
 *   - On leader crash, the TTL expires after ttlMs → another instance takes over
 *
 * SAFETY PROPERTIES:
 *   - At most one leader at any time (guaranteed by Redis SETNX atomicity)
 *   - No split-brain (lease TTL is the authority, not the process)
 *   - Failover time = ttlMs (30s default) — acceptable: worst case 30s gap in polling
 *   - Renewal uses PEXPIRE (not SET NX again) so the lock key is stable
 *   - Graceful shutdown releases the lock immediately (faster failover on controlled restart)
 *
 * FAILURE MODE:
 *   - If Redis is down: both instances fall through to start polling (fail-open)
 *     because a payment gap is worse than a duplicate-detection scenario. The
 *     matching engine's deduplication Redis seen-set also fails in this scenario,
 *     so monitoring must alert on Redis down immediately.
 *
 * PARAMETERS (all tunable via ENV):
 *   LEADER_LOCK_TTL_MS     — Lease TTL (default 30000 = 30s)
 *   LEADER_RENEW_MS        — Renewal interval (default 10000 = 10s — must be < TTL)
 *   LEADER_RETRY_MS        — Non-leader retry interval (default 5000 = 5s)
 *
 * USAGE (in server.js):
 *   const { LeaderElection } = require('./leaderElection');
 *   const leader = new LeaderElection({ redis, logger });
 *   leader.on('elected',   () => listener.start());
 *   leader.on('deposed',   () => listener.stop());
 *   leader.start();
 */

const { EventEmitter } = require('events');
const { createLogger } = require('@xcg/logger');

const LOCK_KEY          = 'xcg:leader:blockchain-listener';
const LOCK_TTL_MS       = parseInt(process.env.LEADER_LOCK_TTL_MS,  10) || 30_000; // 30s
const RENEW_INTERVAL_MS = parseInt(process.env.LEADER_RENEW_MS,     10) || 10_000; // 10s
const RETRY_INTERVAL_MS = parseInt(process.env.LEADER_RETRY_MS,     10) ||  5_000; // 5s

class LeaderElection extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.redis  - IORedis instance
   * @param {object} [opts.logger]
   * @param {string} [opts.instanceId] - Unique ID for this instance (defaults to hostname:PID)
   */
  constructor({ redis, logger, instanceId }) {
    super();
    this.redis      = redis;
    this.logger     = logger || createLogger('leader-election');
    this.instanceId = instanceId || `${require('os').hostname()}:${process.pid}`;

    this._isLeader   = false;
    this._renewTimer = null;
    this._retryTimer = null;
    this._stopped    = false;
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  /** Begin leader election loop. Emits 'elected' when this instance wins. */
  start() {
    this.logger.info('LeaderElection: starting', { instanceId: this.instanceId });
    this._tryAcquire();
  }

  /** Stop election and release lock if leader. */
  async stop() {
    this._stopped = true;
    clearTimeout(this._renewTimer);
    clearTimeout(this._retryTimer);

    if (this._isLeader) {
      this._isLeader = false;
      try {
        // Release immediately on graceful shutdown so another instance can take
        // over in RETRY_INTERVAL_MS rather than LOCK_TTL_MS.
        // Use Lua script to ensure we only delete OUR lock (not a new owner's).
        await this._releaseLock();
        this.logger.info('LeaderElection: released lock on shutdown', { instanceId: this.instanceId });
      } catch (err) {
        this.logger.warn('LeaderElection: failed to release lock on shutdown', { error: err.message });
      }
    }
  }

  /** @returns {boolean} Whether this instance is currently the leader */
  get isLeader() {
    return this._isLeader;
  }

  // ─── Internal ────────────────────────────────────────────────────────────────

  async _tryAcquire() {
    if (this._stopped) return;

    try {
      // SET NX PX: atomic "set if not exists with millisecond TTL"
      // Value = instanceId so we can verify ownership before renewal
      const result = await this.redis.set(
        LOCK_KEY,
        this.instanceId,
        'PX', LOCK_TTL_MS,
        'NX',
      );

      if (result === 'OK') {
        this._isLeader = true;
        this.logger.info('LeaderElection: ELECTED as leader', { instanceId: this.instanceId });
        this.emit('elected');
        this._scheduleRenewal();
      } else {
        // Another instance holds the lock — check who and log for diagnostics
        const holder = await this.redis.get(LOCK_KEY).catch(() => 'unknown');
        this.logger.debug('LeaderElection: not leader — will retry', {
          instanceId: this.instanceId,
          currentLeader: holder,
          retryInMs: RETRY_INTERVAL_MS,
        });
        this._scheduleRetry();
      }
    } catch (err) {
      // Redis unavailable — fail open (both instances will poll — dedup prevents double-credit)
      this.logger.error('LeaderElection: Redis error during acquisition — failing open', {
        instanceId: this.instanceId,
        error: err.message,
      });

      if (!this._isLeader) {
        this._isLeader = true;
        this.logger.warn('LeaderElection: FAIL-OPEN — starting polling without lock', {
          instanceId: this.instanceId,
        });
        this.emit('elected');
      }

      // Retry later in case Redis recovers
      this._scheduleRetry();
    }
  }

  _scheduleRenewal() {
    if (this._stopped) return;
    this._renewTimer = setTimeout(() => this._renewLock(), RENEW_INTERVAL_MS);
  }

  _scheduleRetry() {
    if (this._stopped) return;
    this._retryTimer = setTimeout(() => this._tryAcquire(), RETRY_INTERVAL_MS);
  }

  async _renewLock() {
    if (this._stopped) return;

    try {
      // Verify we still own the lock before renewing
      const currentHolder = await this.redis.get(LOCK_KEY);

      if (currentHolder !== this.instanceId) {
        // Another instance stole the lock (shouldn't happen, but be defensive)
        this.logger.warn('LeaderElection: lock stolen — stepping down', {
          instanceId: this.instanceId,
          currentHolder,
        });
        this._stepDown();
        return;
      }

      // Extend TTL (PEXPIRE keeps the key, just refreshes TTL)
      await this.redis.pexpire(LOCK_KEY, LOCK_TTL_MS);
      this.logger.debug('LeaderElection: lock renewed', { instanceId: this.instanceId });
      this._scheduleRenewal();

    } catch (err) {
      this.logger.error('LeaderElection: renewal failed — stepping down', {
        instanceId: this.instanceId,
        error: err.message,
      });
      this._stepDown();
    }
  }

  _stepDown() {
    if (!this._isLeader) return;
    this._isLeader = false;
    clearTimeout(this._renewTimer);
    this.logger.info('LeaderElection: DEPOSED — stopping polling', { instanceId: this.instanceId });
    this.emit('deposed');
    // Re-enter acquisition loop
    this._scheduleRetry();
  }

  /**
   * Lua script: DEL key only if value matches our instanceId.
   * Prevents accidentally deleting a lock acquired by a new leader during slow shutdown.
   */
  async _releaseLock() {
    const script = `
      if redis.call("get", KEYS[1]) == ARGV[1] then
        return redis.call("del", KEYS[1])
      else
        return 0
      end
    `;
    return this.redis.eval(script, 1, LOCK_KEY, this.instanceId);
  }
}

module.exports = { LeaderElection };
