'use strict';

/**
 * @test packages/common/shutdown
 *
 * Tests the shared registerShutdown + runMain utilities.
 *
 * Since these create process event listeners and call process.exit(),
 * we mock process signals and exit to avoid actually killing the test runner.
 */

// Mock @xcg/database — disconnectDB
const mockDisconnectDB = jest.fn().mockResolvedValue(undefined);
jest.mock('@xcg/database', () => ({
  disconnectDB: (...args) => mockDisconnectDB(...args),
}));

const { registerShutdown, runMain, FORCE_KILL_TIMEOUT_MS } = require('../src/shutdown');

// ── Test Helpers ──────────────────────────────────────────────────────────────

const createLogger = () => ({
  info:  jest.fn(),
  warn:  jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
});

describe('shutdown utility', () => {
  let originalExit;
  let originalOn;
  const listeners = {};

  beforeEach(() => {
    jest.clearAllMocks();

    // Mock process.exit
    originalExit = process.exit;
    process.exit = jest.fn();

    // Mock process.on — capture listeners
    originalOn = process.on;
    process.on = jest.fn((event, handler) => {
      listeners[event] = handler;
    });
  });

  afterEach(() => {
    process.exit = originalExit;
    process.on = originalOn;
    Object.keys(listeners).forEach((k) => delete listeners[k]);
  });

  // ── FORCE_KILL_TIMEOUT_MS ───────────────────────────────────────────────────

  test('FORCE_KILL_TIMEOUT_MS is 30 seconds', () => {
    expect(FORCE_KILL_TIMEOUT_MS).toBe(30_000);
  });

  // ── registerShutdown ────────────────────────────────────────────────────────

  describe('registerShutdown()', () => {
    test('registers SIGTERM, SIGINT, uncaughtException, unhandledRejection', () => {
      const logger = createLogger();
      registerShutdown({ logger, service: 'test-svc', cleanup: async () => {} });

      const registeredEvents = process.on.mock.calls.map((c) => c[0]);
      expect(registeredEvents).toContain('SIGTERM');
      expect(registeredEvents).toContain('SIGINT');
      expect(registeredEvents).toContain('uncaughtException');
      expect(registeredEvents).toContain('unhandledRejection');
    });

    test('calls cleanup + disconnectDB on signal', async () => {
      const logger = createLogger();
      const mockCleanup = jest.fn().mockResolvedValue(undefined);

      registerShutdown({ logger, service: 'test-svc', cleanup: mockCleanup });

      // Trigger SIGTERM handler
      const sigterm = listeners['SIGTERM'];
      expect(sigterm).toBeDefined();
      await sigterm();

      // Cleanup was called
      expect(mockCleanup).toHaveBeenCalledTimes(1);

      // disconnectDB was called
      expect(mockDisconnectDB).toHaveBeenCalledTimes(1);

      // process.exit(0) was called
      expect(process.exit).toHaveBeenCalledWith(0);
    });

    test('skips disconnectDB when skipDbDisconnect=true', async () => {
      const logger = createLogger();

      registerShutdown({
        logger,
        service: 'test-svc',
        cleanup: async () => {},
        skipDbDisconnect: true,
      });

      await listeners['SIGTERM']();

      expect(mockDisconnectDB).not.toHaveBeenCalled();
      expect(process.exit).toHaveBeenCalledWith(0);
    });

    test('handles cleanup errors gracefully', async () => {
      const logger = createLogger();
      const badCleanup = jest.fn().mockRejectedValue(new Error('cleanup exploded'));

      registerShutdown({ logger, service: 'test-svc', cleanup: badCleanup });

      await listeners['SIGTERM']();

      // Should still exit (with code 1 due to error)
      expect(process.exit).toHaveBeenCalledWith(1);
      expect(logger.error).toHaveBeenCalled();
    });

    test('handles disconnectDB errors as non-fatal', async () => {
      const logger = createLogger();
      mockDisconnectDB.mockRejectedValueOnce(new Error('mongo disconnect failed'));

      registerShutdown({ logger, service: 'test-svc', cleanup: async () => {} });

      await listeners['SIGTERM']();

      // Should still exit 0 (DB disconnect failure is non-fatal)
      expect(process.exit).toHaveBeenCalledWith(0);
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining('MongoDB disconnect error'),
        expect.any(Object),
      );
    });
  });

  // ── runMain ─────────────────────────────────────────────────────────────────

  describe('runMain()', () => {
    test('calls logger.error on main() rejection', async () => {
      const logger = createLogger();

      // Spy on console.error (runMain uses it as fallback)
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

      runMain(
        () => Promise.reject(new Error('startup exploded')),
        { logger, service: 'test-svc' },
      );

      // Wait for the catch handler to fire
      await new Promise((r) => setTimeout(r, 50));

      // Logger was used (not just console.error)
      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining('fatal startup error'),
        expect.objectContaining({ error: 'startup exploded' }),
      );

      // process.exit(1) called
      expect(process.exit).toHaveBeenCalledWith(1);

      consoleErrorSpy.mockRestore();
    });

    test('does not call logger.error on successful main()', async () => {
      const logger = createLogger();

      runMain(
        () => Promise.resolve(),
        { logger, service: 'test-svc' },
      );

      await new Promise((r) => setTimeout(r, 50));

      expect(logger.error).not.toHaveBeenCalled();
      expect(process.exit).not.toHaveBeenCalled();
    });
  });
});
