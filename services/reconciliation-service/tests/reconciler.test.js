'use strict';

/**
 * @test reconciliation-service/reconciler
 *
 * Tests the Reconciler — on-chain vs ledger balance comparison.
 *
 * Mocks:
 *   - @xcg/database (Wallet, LedgerEntry, Invoice, ReconciliationReport) → in-memory
 *   - tronAdapter.getUSDTBalance → controlled returns
 *   - redis → mock SET/GET/DEL
 *   - alertPublisher → mock publish
 */

// ── Mock DB models ──────────────────────────────────────────────────────────

const mockWalletFind = jest.fn();
const mockInvoiceFind = jest.fn();
const mockLedgerAggregate = jest.fn();
const mockReportCreate = jest.fn();
const mockReportFindOne = jest.fn();
const mockReportFindByIdAndUpdate = jest.fn();

jest.mock('@xcg/database', () => ({
  Wallet: {
    find: (...args) => ({
      select: () => ({ lean: () => mockWalletFind(...args) }),
    }),
  },
  Invoice: {
    find: (...args) => ({
      select: () => ({ lean: () => mockInvoiceFind(...args) }),
    }),
  },
  LedgerEntry: {
    aggregate: (...args) => mockLedgerAggregate(...args),
  },
  ReconciliationReport: {
    create: (...args) => mockReportCreate(...args),
    findOne: (...args) => mockReportFindOne(...args),
    findByIdAndUpdate: (...args) => mockReportFindByIdAndUpdate(...args),
  },
}));

const Reconciler = require('../src/reconciler');

// ── Test Helpers ──────────────────────────────────────────────────────────────

const createLogger = () => ({
  info:  jest.fn(),
  warn:  jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
});

const createMockRedis = () => ({
  set:   jest.fn().mockResolvedValue('OK'),
  get:   jest.fn().mockResolvedValue(null),
  del:   jest.fn().mockResolvedValue(1),
  quit:  jest.fn().mockResolvedValue('OK'),
});

const createMockRedisSub = () => ({
  subscribe:   jest.fn().mockImplementation((ch, cb) => cb(null)),
  unsubscribe: jest.fn().mockResolvedValue('OK'),
  on:          jest.fn(),
  quit:        jest.fn().mockResolvedValue('OK'),
});

const createMockTronAdapter = () => ({
  getUSDTBalance: jest.fn(),
});

const createMockAlertPublisher = () => ({
  publish: jest.fn().mockResolvedValue(undefined),
});

const wallet1 = { _id: 'w1', address: 'TAddr111', label: 'hot-1', balance: 100 };
const wallet2 = { _id: 'w2', address: 'TAddr222', label: 'hot-2', balance: 200 };

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Reconciler', () => {
  let reconciler;
  let logger;
  let redis;
  let redisSub;
  let tronAdapter;
  let alertPublisher;

  beforeEach(() => {
    jest.clearAllMocks();
    logger         = createLogger();
    redis          = createMockRedis();
    redisSub       = createMockRedisSub();
    tronAdapter    = createMockTronAdapter();
    alertPublisher = createMockAlertPublisher();

    reconciler = new Reconciler({ tronAdapter, redis, redisSub, alertPublisher, logger });

    // Default: report creation succeeds
    mockReportCreate.mockImplementation((data) => Promise.resolve({ _id: 'rpt_id', ...data }));
    mockReportFindByIdAndUpdate.mockResolvedValue({});

    // Default: no invoices/ledger entries
    mockInvoiceFind.mockResolvedValue([]);
    mockLedgerAggregate.mockResolvedValue([]);
  });

  // ── All Wallets Balanced ────────────────────────────────────────────────────

  describe('_run() — all wallets balanced', () => {
    test('returns passed:true and does not pause withdrawals', async () => {
      mockWalletFind.mockResolvedValue([wallet1, wallet2]);
      tronAdapter.getUSDTBalance
        .mockResolvedValueOnce('100.000000')  // wallet1
        .mockResolvedValueOnce('200.000000'); // wallet2

      // Ledger matches (100 + 200)
      mockInvoiceFind
        .mockResolvedValueOnce([{ _id: 'inv1' }])
        .mockResolvedValueOnce([{ _id: 'inv2' }]);
      mockLedgerAggregate
        .mockResolvedValueOnce([{ _id: null, credits: 100, debits: 0 }])
        .mockResolvedValueOnce([{ _id: null, credits: 200, debits: 0 }]);

      const report = { reportId: 'test_report_1' };
      const result = await reconciler._run(report);

      expect(result.passed).toBe(true);
      expect(result.walletsChecked).toBe(2);
      expect(result.mismatches).toHaveLength(0);
      expect(result.pausedWithdrawals).toBe(false);
      expect(result.alertSent).toBe(false);
    });

    test('lifts reconciler-set pause when all wallets clean', async () => {
      mockWalletFind.mockResolvedValue([wallet1]);
      tronAdapter.getUSDTBalance.mockResolvedValue('100.000000');
      mockInvoiceFind.mockResolvedValue([{ _id: 'inv1' }]);
      mockLedgerAggregate.mockResolvedValue([{ _id: null, credits: 100, debits: 0 }]);

      // Simulate existing reconciler-set pause
      redis.get.mockResolvedValue('reconciliation_mismatch');

      const report = { reportId: 'test_report_2' };
      await reconciler._run(report);

      // Should lift the pause
      expect(redis.del).toHaveBeenCalledWith('xcg:system:withdrawals_paused');
      expect(redis.del).toHaveBeenCalledWith('xcg:system:withdrawals_pause_reason');
    });

    test('preserves admin-set pause even when wallets clean', async () => {
      mockWalletFind.mockResolvedValue([wallet1]);
      tronAdapter.getUSDTBalance.mockResolvedValue('100.000000');
      mockInvoiceFind.mockResolvedValue([{ _id: 'inv1' }]);
      mockLedgerAggregate.mockResolvedValue([{ _id: null, credits: 100, debits: 0 }]);

      // Simulate admin-set pause
      redis.get.mockResolvedValue('admin_manual_pause');

      const report = { reportId: 'test_report_3' };
      await reconciler._run(report);

      // Should NOT lift the admin pause
      expect(redis.del).not.toHaveBeenCalled();
      expect(logger.info).toHaveBeenCalledWith(
        expect.stringContaining('pause kept (set by admin'),
      );
    });
  });

  // ── Mismatch Detection ──────────────────────────────────────────────────────

  describe('_run() — mismatch detected', () => {
    test('detects mismatch, pauses withdrawals, sends alert', async () => {
      mockWalletFind.mockResolvedValue([wallet1]);
      tronAdapter.getUSDTBalance.mockResolvedValue('150.000000'); // on-chain: 150
      mockInvoiceFind.mockResolvedValue([{ _id: 'inv1' }]);
      mockLedgerAggregate.mockResolvedValue([{ _id: null, credits: 100, debits: 0 }]); // ledger: 100

      const report = { reportId: 'test_mismatch_1' };
      const result = await reconciler._run(report);

      expect(result.passed).toBe(false);
      expect(result.mismatches).toHaveLength(1);
      expect(result.mismatches[0].onChainBalance).toBe(150);
      expect(result.mismatches[0].ledgerBalance).toBe(100);
      expect(result.mismatches[0].difference).toBe(50);
      expect(result.pausedWithdrawals).toBe(true);
      expect(result.alertSent).toBe(true);

      // Redis pause set
      expect(redis.set).toHaveBeenCalledWith(
        'xcg:system:withdrawals_paused', '1', 'EX', 86400,
      );

      // Alert published
      expect(alertPublisher.publish).toHaveBeenCalledTimes(1);
    });

    test('classifies severity: critical for >$100 diff', async () => {
      mockWalletFind.mockResolvedValue([wallet1]);
      tronAdapter.getUSDTBalance.mockResolvedValue('300.000000'); // 300 vs 100 = 200 diff
      mockInvoiceFind.mockResolvedValue([{ _id: 'inv1' }]);
      mockLedgerAggregate.mockResolvedValue([{ _id: null, credits: 100, debits: 0 }]);

      const result = await reconciler._run({ reportId: 'test_crit_1' });
      expect(result.mismatches[0].severity).toBe('critical');
    });

    test('classifies severity: major for $1-$100 diff', async () => {
      mockWalletFind.mockResolvedValue([wallet1]);
      tronAdapter.getUSDTBalance.mockResolvedValue('110.000000'); // 110 vs 100 = 10 diff
      mockInvoiceFind.mockResolvedValue([{ _id: 'inv1' }]);
      mockLedgerAggregate.mockResolvedValue([{ _id: null, credits: 100, debits: 0 }]);

      const result = await reconciler._run({ reportId: 'test_major_1' });
      expect(result.mismatches[0].severity).toBe('major');
    });

    test('classifies severity: minor for <$1 diff', async () => {
      mockWalletFind.mockResolvedValue([wallet1]);
      tronAdapter.getUSDTBalance.mockResolvedValue('100.500000'); // 100.5 vs 100 = 0.5 diff
      mockInvoiceFind.mockResolvedValue([{ _id: 'inv1' }]);
      mockLedgerAggregate.mockResolvedValue([{ _id: null, credits: 100, debits: 0 }]);

      const result = await reconciler._run({ reportId: 'test_minor_1' });
      expect(result.mismatches[0].severity).toBe('minor');
    });
  });

  // ── Error Handling ──────────────────────────────────────────────────────────

  describe('_run() — error handling', () => {
    test('continues when single wallet check throws', async () => {
      mockWalletFind.mockResolvedValue([wallet1, wallet2]);

      // wallet1 throws
      tronAdapter.getUSDTBalance
        .mockRejectedValueOnce(new Error('TronGrid timeout'))
        .mockResolvedValueOnce('200.000000'); // wallet2 ok

      mockInvoiceFind.mockResolvedValue([{ _id: 'inv2' }]);
      mockLedgerAggregate.mockResolvedValue([{ _id: null, credits: 200, debits: 0 }]);

      const result = await reconciler._run({ reportId: 'test_error_1' });

      // Both wallets checked (one failed, one ok)
      expect(result.walletsChecked).toBe(2);

      // Failed wallet still shows in mismatches (with 0 values)
      expect(result.mismatches).toHaveLength(1);
      expect(result.mismatches[0].walletAddress).toBe('TAddr111');

      // Error logged
      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining('failed to check wallet'),
        expect.objectContaining({ address: 'TAddr111' }),
      );
    });
  });

  // ── Report Lifecycle ────────────────────────────────────────────────────────

  describe('_runWithReport() — lifecycle', () => {
    test('prevents overlapping runs', async () => {
      // Simulate _running = true
      reconciler._running = true;

      await reconciler._runWithReport({ triggeredBy: 'scheduler' });

      expect(mockReportCreate).not.toHaveBeenCalled();
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining('run already in progress'),
      );

      reconciler._running = false; // cleanup
    });

    test('marks report as failed when _run() throws', async () => {
      mockReportCreate.mockResolvedValue({ _id: 'rpt_fail_1', reportId: 'fail_1' });
      mockWalletFind.mockRejectedValue(new Error('DB connection lost'));

      await reconciler._runWithReport({ triggeredBy: 'scheduler' });

      expect(mockReportFindByIdAndUpdate).toHaveBeenCalledWith(
        'rpt_fail_1',
        expect.objectContaining({
          $set: expect.objectContaining({
            status: 'failed',
            passed: false,
            error: 'DB connection lost',
          }),
        }),
      );
    });

    test('creates new report for scheduled runs', async () => {
      mockReportCreate.mockResolvedValue({ _id: 'rpt_sched_1', reportId: 'recon_xxx' });
      mockWalletFind.mockResolvedValue([]); // no wallets

      await reconciler._runWithReport({ triggeredBy: 'scheduler' });

      expect(mockReportCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          triggeredBy: 'scheduler',
          status: 'running',
        }),
      );
    });

    test('uses existing report for manual triggers', async () => {
      const existingReport = { _id: 'rpt_manual_1', reportId: 'manual_report_123' };
      mockReportFindOne.mockResolvedValue(existingReport);
      mockWalletFind.mockResolvedValue([]); // no wallets

      await reconciler._runWithReport({
        triggeredBy: 'admin_user_id',
        existingReportId: 'manual_report_123',
      });

      // Should look up existing report, not create new
      expect(mockReportFindOne).toHaveBeenCalledWith({ reportId: 'manual_report_123' });
      expect(mockReportCreate).not.toHaveBeenCalled();
    });
  });
});
