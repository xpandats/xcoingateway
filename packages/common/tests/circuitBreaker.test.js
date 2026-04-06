'use strict';

/**
 * @test packages/common/circuitBreaker
 *
 * Tests the CircuitBreaker FSM — CLOSED → OPEN → HALF_OPEN → CLOSED lifecycle.
 *
 * No external mocks needed — the circuit breaker is a pure state machine.
 * We just pass in async functions that succeed or fail on demand.
 */

// Suppress logger noise in tests
jest.mock('@xcg/logger', () => ({
  createLogger: () => ({
    info:  jest.fn(),
    warn:  jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  }),
}));

const { CircuitBreaker, CircuitOpenError, STATE } = require('../src/circuitBreaker');

// Helper: create a breaker with fast timers for testing
function createTestBreaker(overrides = {}) {
  return new CircuitBreaker('test', {
    failureThreshold: 3,
    successThreshold: 2,
    openDurationMs:   100,   // 100ms — fast for tests
    resetTimeMs:      200,   // 200ms failure window
    ...overrides,
  });
}

describe('CircuitBreaker', () => {

  // ── Initial State ───────────────────────────────────────────────────────────

  test('starts in CLOSED state', () => {
    const breaker = createTestBreaker();
    expect(breaker.state).toBe(STATE.CLOSED);
    expect(breaker.isClosed).toBe(true);
    expect(breaker.isOpen).toBe(false);
  });

  // ── CLOSED → OPEN ──────────────────────────────────────────────────────────

  describe('CLOSED → OPEN transition', () => {
    test('opens after failureThreshold consecutive failures', async () => {
      const breaker = createTestBreaker({ failureThreshold: 3 });

      const fail = () => { throw new Error('fail'); };

      // 3 failures → should open
      for (let i = 0; i < 3; i++) {
        await expect(breaker.execute(fail)).rejects.toThrow('fail');
      }

      expect(breaker.state).toBe(STATE.OPEN);
      expect(breaker.isOpen).toBe(true);
    });

    test('stays CLOSED when failures are below threshold', async () => {
      const breaker = createTestBreaker({ failureThreshold: 5 });

      const fail = () => { throw new Error('fail'); };

      // 3 failures (threshold is 5) → should stay closed
      for (let i = 0; i < 3; i++) {
        await expect(breaker.execute(fail)).rejects.toThrow();
      }

      expect(breaker.state).toBe(STATE.CLOSED);
    });

    test('resets failure counter after resetTimeMs window expires', async () => {
      const breaker = createTestBreaker({ failureThreshold: 3, resetTimeMs: 50 });

      const fail = () => { throw new Error('fail'); };

      // 2 failures
      for (let i = 0; i < 2; i++) {
        await expect(breaker.execute(fail)).rejects.toThrow();
      }

      // Wait for window to expire
      await new Promise((r) => setTimeout(r, 60));

      // 2 more failures (counter reset) → should NOT open (only 2 in new window)
      for (let i = 0; i < 2; i++) {
        await expect(breaker.execute(fail)).rejects.toThrow();
      }

      expect(breaker.state).toBe(STATE.CLOSED);
    });
  });

  // ── OPEN → rejects ─────────────────────────────────────────────────────────

  describe('OPEN state', () => {
    test('rejects immediately with CircuitOpenError', async () => {
      const breaker = createTestBreaker({ failureThreshold: 1 });

      await expect(breaker.execute(() => { throw new Error('x'); })).rejects.toThrow();
      expect(breaker.state).toBe(STATE.OPEN);

      // Next call should fast-fail
      try {
        await breaker.execute(() => 'should not run');
        throw new Error('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(CircuitOpenError);
        expect(err.code).toBe('CIRCUIT_OPEN');
        expect(err.isCircuitOpen).toBe(true);
        expect(err.retryInSec).toBeGreaterThan(0);
      }
    });
  });

  // ── OPEN → HALF_OPEN ───────────────────────────────────────────────────────

  describe('OPEN → HALF_OPEN transition', () => {
    test('transitions to HALF_OPEN after openDurationMs', async () => {
      const breaker = createTestBreaker({ failureThreshold: 1, openDurationMs: 50 });

      await expect(breaker.execute(() => { throw new Error('x'); })).rejects.toThrow();
      expect(breaker.state).toBe(STATE.OPEN);

      // Wait for open duration
      await new Promise((r) => setTimeout(r, 60));

      // Next execute should transition to HALF_OPEN and let the call through
      const result = await breaker.execute(() => 'probe-ok');
      expect(result).toBe('probe-ok');
      // After 1 success with successThreshold=2, still HALF_OPEN
    });
  });

  // ── HALF_OPEN → CLOSED ─────────────────────────────────────────────────────

  describe('HALF_OPEN → CLOSED transition', () => {
    test('closes after successThreshold probe successes', async () => {
      const breaker = createTestBreaker({
        failureThreshold: 1,
        successThreshold: 2,
        openDurationMs: 50,
      });

      // Force OPEN
      await expect(breaker.execute(() => { throw new Error('x'); })).rejects.toThrow();
      await new Promise((r) => setTimeout(r, 60));

      // First probe success → still HALF_OPEN
      await breaker.execute(() => 'ok-1');
      expect(breaker.state).toBe(STATE.HALF_OPEN);

      // Second probe success → CLOSED
      await breaker.execute(() => 'ok-2');
      expect(breaker.state).toBe(STATE.CLOSED);
    });
  });

  // ── HALF_OPEN → OPEN ───────────────────────────────────────────────────────

  describe('HALF_OPEN → OPEN (probe failure)', () => {
    test('reopens on probe failure', async () => {
      const breaker = createTestBreaker({
        failureThreshold: 1,
        openDurationMs: 50,
      });

      // Force OPEN
      await expect(breaker.execute(() => { throw new Error('x'); })).rejects.toThrow();
      await new Promise((r) => setTimeout(r, 60));

      // Probe fails → back to OPEN
      await expect(breaker.execute(() => { throw new Error('probe-fail'); })).rejects.toThrow();
      expect(breaker.state).toBe(STATE.OPEN);
    });
  });

  // ── Events ──────────────────────────────────────────────────────────────────

  describe('event emission', () => {
    test('emits open, close, half-open, reject events', async () => {
      const breaker = createTestBreaker({
        failureThreshold: 1,
        successThreshold: 1,
        openDurationMs: 50,
      });

      const events = [];
      breaker.on('open',      () => events.push('open'));
      breaker.on('close',     () => events.push('close'));
      breaker.on('half-open', () => events.push('half-open'));
      breaker.on('reject',    () => events.push('reject'));

      // Trigger OPEN
      await expect(breaker.execute(() => { throw new Error('x'); })).rejects.toThrow();
      expect(events).toContain('open');

      // Trigger reject
      try { await breaker.execute(() => 'x'); } catch { /* expected */ }
      expect(events).toContain('reject');

      // Wait for HALF_OPEN
      await new Promise((r) => setTimeout(r, 60));
      await breaker.execute(() => 'ok');
      expect(events).toContain('half-open');
      expect(events).toContain('close');
    });
  });

  // ── toJSON ──────────────────────────────────────────────────────────────────

  describe('toJSON()', () => {
    test('returns correct metrics snapshot', async () => {
      const breaker = createTestBreaker();

      const json = breaker.toJSON();
      expect(json).toHaveProperty('name', 'test');
      expect(json).toHaveProperty('state', STATE.CLOSED);
      expect(json).toHaveProperty('failures', 0);
      expect(json).toHaveProperty('failureThreshold', 3);
      expect(json).toHaveProperty('lastFailureAt', null);
      expect(json).toHaveProperty('openedAt', null);
    });
  });

  // ── Successes in CLOSED ─────────────────────────────────────────────────────

  describe('success in CLOSED state', () => {
    test('passes through without state change', async () => {
      const breaker = createTestBreaker();

      const result = await breaker.execute(() => 'hello');
      expect(result).toBe('hello');
      expect(breaker.state).toBe(STATE.CLOSED);
    });
  });
});
