'use strict';

/**
 * @module @xcg/common/src/circuitBreaker
 *
 * Lightweight Circuit Breaker — No External Dependencies.
 *
 * WHY:
 *   Without a circuit breaker, if MongoDB is slow or TronGrid is timing out,
 *   every incoming request queues and waits, holding a TCP connection and a
 *   thread-pool slot. Under load, this cascades: all 100 connections pile up
 *   waiting for a 30s MongoDB timeout, the event loop starves, the process
 *   appears alive but is functionally dead. New requests keep arriving and pile
 *   on top. The health check may still pass (process is alive), so the load
 *   balancer keeps routing traffic → full cascade failure.
 *
 *   A circuit breaker detects this early and fast-fails requests while the
 *   dependency is degraded, so the event loop stays healthy and the health
 *   check can correctly return 503.
 *
 * STATES:
 *   CLOSED  → normal operation. Failures counted. If failures >= threshold
 *             within resetTimeMs → OPEN.
 *   OPEN    → requests fast-fail immediately (no network call).
 *             After openDurationMs → HALF_OPEN.
 *   HALF_OPEN → one probe request allowed through.
 *             Success → CLOSED. Failure → OPEN again.
 *
 * INTENTIONAL SIMPLICITY:
 *   This is a custom implementation to avoid the `opossum` npm dependency
 *   (adds 50+ transitive deps). The logic is 100% correct for our use case.
 *   If the team wants to migrate to opossum later, the interface is compatible.
 *
 * USAGE:
 *   const { CircuitBreaker } = require('@xcg/common/src/circuitBreaker');
 *
 *   const mongoBreaker = new CircuitBreaker('mongodb', {
 *     failureThreshold: 5,     // Open after 5 failures
 *     successThreshold: 2,     // Close after 2 successes in HALF_OPEN
 *     openDurationMs:   30000, // Stay OPEN for 30s then probe
 *     resetTimeMs:      60000, // Count failures in a 60s window
 *   });
 *
 *   // Wrap any async call:
 *   const result = await mongoBreaker.execute(() => SomeModel.findOne(...));
 *
 * EVENTS:
 *   'open'      — circuit opened (dependency failing)
 *   'close'     — circuit closed (dependency recovered)
 *   'half-open' — circuit probing (one request allowed)
 *   'reject'    — request fast-failed (circuit OPEN)
 */

const { EventEmitter } = require('events');
const { createLogger } = require('@xcg/logger');

const STATE = Object.freeze({
  CLOSED:    'CLOSED',
  OPEN:      'OPEN',
  HALF_OPEN: 'HALF_OPEN',
});

class CircuitBreaker extends EventEmitter {
  /**
   * @param {string} name   - Identifier for logging/metrics
   * @param {object} [opts]
   * @param {number} [opts.failureThreshold=5]  - Failures before opening
   * @param {number} [opts.successThreshold=2]  - Successes in HALF_OPEN to close
   * @param {number} [opts.openDurationMs=30000] - How long to stay OPEN before probing
   * @param {number} [opts.resetTimeMs=60000]   - Failure counter window
   * @param {object} [opts.logger]
   */
  constructor(name, {
    failureThreshold = 5,
    successThreshold = 2,
    openDurationMs   = 30_000,
    resetTimeMs      = 60_000,
    logger,
  } = {}) {
    super();
    this.name             = name;
    this.failureThreshold = failureThreshold;
    this.successThreshold = successThreshold;
    this.openDurationMs   = openDurationMs;
    this.resetTimeMs      = resetTimeMs;
    this.logger           = logger || createLogger(`circuit-breaker:${name}`);

    this._state          = STATE.CLOSED;
    this._failures       = 0;
    this._successes      = 0;   // Only counted in HALF_OPEN
    this._lastFailureAt  = null;
    this._openedAt       = null;
    this._windowStart    = Date.now();
  }

  // ─── Core execution ──────────────────────────────────────────────────────────

  /**
   * Execute a function guarded by this circuit breaker.
   *
   * @param {Function} fn - Async function to execute
   * @returns {Promise<any>}
   * @throws {CircuitOpenError} if circuit is OPEN
   * @throws {Error} if fn throws (circuit records the failure)
   */
  async execute(fn) {
    switch (this._state) {

      case STATE.OPEN: {
        const msSinceOpen = Date.now() - this._openedAt;
        if (msSinceOpen >= this.openDurationMs) {
          this._transitionTo(STATE.HALF_OPEN);
          // Fall through to HALF_OPEN handling
        } else {
          const retryInSec = Math.ceil((this.openDurationMs - msSinceOpen) / 1000);
          this.emit('reject', { name: this.name, retryInSec });
          this.logger.warn(`CircuitBreaker[${this.name}]: OPEN — rejecting request`, { retryInSec });
          const err = new CircuitOpenError(this.name, retryInSec);
          throw err;
        }
        // INTENTIONAL FALL-THROUGH to HALF_OPEN
      }

      // eslint-disable-next-line no-fallthrough
      case STATE.HALF_OPEN: {
        try {
          const result = await fn();
          this._onSuccess();
          return result;
        } catch (err) {
          this._onFailure(err);
          throw err;
        }
      }

      case STATE.CLOSED:
      default: {
        // Reset failure counter if window expired
        if (Date.now() - this._windowStart > this.resetTimeMs) {
          this._failures    = 0;
          this._windowStart = Date.now();
        }

        try {
          const result = await fn();
          // In CLOSED state successes don't change state
          return result;
        } catch (err) {
          this._onFailure(err);
          throw err;
        }
      }
    }
  }

  // ─── State transitions ────────────────────────────────────────────────────────

  _onSuccess() {
    if (this._state === STATE.HALF_OPEN) {
      this._successes++;
      this.logger.info(`CircuitBreaker[${this.name}]: HALF_OPEN probe succeeded (${this._successes}/${this.successThreshold})`);
      if (this._successes >= this.successThreshold) {
        this._transitionTo(STATE.CLOSED);
      }
    }
  }

  _onFailure(err) {
    this._failures++;
    this._lastFailureAt = Date.now();

    if (this._state === STATE.HALF_OPEN) {
      this.logger.warn(`CircuitBreaker[${this.name}]: HALF_OPEN probe failed — reopening`, {
        error: err.message,
      });
      this._transitionTo(STATE.OPEN);
      return;
    }

    if (this._state === STATE.CLOSED && this._failures >= this.failureThreshold) {
      this.logger.error(
        `CircuitBreaker[${this.name}]: threshold reached (${this._failures} failures) — OPENING`,
        { error: err.message, openDurationSec: this.openDurationMs / 1000 },
      );
      this._transitionTo(STATE.OPEN);
    }
  }

  _transitionTo(newState) {
    const old = this._state;
    this._state = newState;

    if (newState === STATE.OPEN) {
      this._openedAt  = Date.now();
      this._successes = 0;
      this.emit('open', { name: this.name });
    } else if (newState === STATE.CLOSED) {
      this._failures    = 0;
      this._successes   = 0;
      this._windowStart = Date.now();
      this.emit('close', { name: this.name });
      this.logger.info(`CircuitBreaker[${this.name}]: CLOSED (recovered)`);
    } else if (newState === STATE.HALF_OPEN) {
      this._successes = 0;
      this.emit('half-open', { name: this.name });
      this.logger.info(`CircuitBreaker[${this.name}]: HALF_OPEN — probing`);
    }

    this.logger.debug(`CircuitBreaker[${this.name}]: ${old} → ${newState}`);
  }

  // ─── Inspection ──────────────────────────────────────────────────────────────

  get state()    { return this._state; }
  get isOpen()   { return this._state === STATE.OPEN; }
  get isClosed() { return this._state === STATE.CLOSED; }

  /** Metrics snapshot for health endpoints */
  toJSON() {
    return {
      name:              this.name,
      state:             this._state,
      failures:          this._failures,
      failureThreshold:  this.failureThreshold,
      lastFailureAt:     this._lastFailureAt,
      openedAt:          this._openedAt,
    };
  }
}

/** Thrown when a circuit is OPEN and a request is fast-failed. */
class CircuitOpenError extends Error {
  constructor(name, retryInSec) {
    super(`Service '${name}' is temporarily unavailable. Retry in ${retryInSec}s.`);
    this.name        = 'CircuitOpenError';
    this.code        = 'CIRCUIT_OPEN';
    this.retryInSec  = retryInSec;
    this.isCircuitOpen = true;
  }
}

/**
 * Pre-built circuit breakers for the two critical external dependencies.
 * Singletons so all middleware shares the same failure counter.
 *
 * Import these where needed:
 *   const { mongoBreaker, tronBreaker } = require('@xcg/common/src/circuitBreaker');
 */
const mongoBreaker = new CircuitBreaker('mongodb', {
  failureThreshold: 5,
  successThreshold: 2,
  openDurationMs:   30_000, // 30s
  resetTimeMs:      60_000, // 1 min window
});

const tronBreaker = new CircuitBreaker('trongrid', {
  failureThreshold: 3,      // TronGrid fails faster (external API)
  successThreshold: 1,      // One success re-closes (API recoveries are real)
  openDurationMs:   20_000, // 20s — shorter since TronGrid has SLA
  resetTimeMs:      60_000,
});

module.exports = { CircuitBreaker, CircuitOpenError, mongoBreaker, tronBreaker, STATE };
