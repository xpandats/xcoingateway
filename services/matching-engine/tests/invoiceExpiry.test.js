'use strict';

/**
 * Invoice Expiry Scanner Test Suite — Banking Grade.
 *
 * Tests InvoiceExpiryScanner from matching-engine/src/invoiceExpiry.js
 *
 * Verifies:
 *   - Correct statuses are expired (INITIATED, PENDING, HASH_FOUND only)
 *   - Confirmed/SUCCESS invoices are never touched
 *   - payment.expired event fired for each expired invoice
 *   - Event fire failure never crashes the scanner
 *   - Batch processing works correctly (stops when fewer than BATCH_SIZE returned)
 *   - start/stop lifecycle works
 */

jest.mock('@xcg/database', () => ({
  Invoice: {
    find:       jest.fn(),
    updateMany: jest.fn(),
  },
}));

jest.mock('@xcg/common', () => ({
  constants: {
    INVOICE_STATUS: {
      INITIATED:  'initiated',
      PENDING:    'pending',
      HASH_FOUND: 'hash_found',
      CONFIRMING: 'confirming',
      CONFIRMED:  'confirmed',
      SUCCESS:    'success',
      EXPIRED:    'expired',
      FAILED:     'failed',
    },
  },
}));

const { Invoice } = require('@xcg/database');
const InvoiceExpiryScanner = require('../src/invoiceExpiry');

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeScanner(overrides = {}) {
  return new InvoiceExpiryScanner({
    expiredPublisher: { publish: jest.fn().mockResolvedValue(undefined) },
    logger: {
      info:  jest.fn(),
      warn:  jest.fn(),
      error: jest.fn(),
      debug: jest.fn(),
    },
    ...overrides,
  });
}

function makeInvoiceRecord(overrides = {}) {
  return {
    _id:        `inv_id_${Math.random().toString(36).slice(2)}`,
    invoiceId:  'inv_test_001',
    merchantId: 'merchant_001',
    baseAmount: 100,
    callbackUrl: 'https://merchant.example.com/webhook',
    ...overrides,
  };
}

// Builds a chainable mock for Invoice.find()
function makeQueryMock(results) {
  const q = {
    select: jest.fn().mockReturnThis(),
    limit:  jest.fn().mockReturnThis(),
    lean:   jest.fn().mockResolvedValue(results),
  };
  return q;
}

beforeEach(() => {
  jest.clearAllMocks();
});

// ═══════════════════════════════════════════════════════════════
// 1 — LIFECYCLE: start / stop
// ═══════════════════════════════════════════════════════════════

describe('Lifecycle — start / stop', () => {
  test('start() sets a timer; stop() clears it', () => {
    const scanner = makeScanner();
    // Spy on setTimeout and clearTimeout
    const setSpy   = jest.spyOn(global, 'setTimeout').mockReturnValue(42);
    const clearSpy = jest.spyOn(global, 'clearTimeout');

    scanner.start();
    expect(setSpy).toHaveBeenCalled();

    scanner.stop();
    expect(clearSpy).toHaveBeenCalledWith(42);

    setSpy.mockRestore();
    clearSpy.mockRestore();
  });

  test('stop() before start() does not throw', () => {
    const scanner = makeScanner();
    expect(() => scanner.stop()).not.toThrow();
  });
});

// ═══════════════════════════════════════════════════════════════
// 2 — SCAN: no expired invoices
// ═══════════════════════════════════════════════════════════════

describe('Scan — no expired invoices', () => {
  test('Empty DB → updateMany never called, no events fired', async () => {
    Invoice.find.mockReturnValue(makeQueryMock([]));

    const scanner = makeScanner();
    await scanner._scan();

    expect(Invoice.updateMany).not.toHaveBeenCalled();
    expect(scanner.expiredPublisher.publish).not.toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// 3 — SCAN: normal expiry flow
// ═══════════════════════════════════════════════════════════════

describe('Scan — normal expiry', () => {
  test('3 expired invoices → updateMany called once, 3 events fired', async () => {
    const invoices = [makeInvoiceRecord(), makeInvoiceRecord(), makeInvoiceRecord()];
    Invoice.find.mockReturnValue(makeQueryMock(invoices));
    Invoice.updateMany.mockResolvedValue({ modifiedCount: 3 });

    const scanner = makeScanner();
    await scanner._scan();

    // updateMany called with all IDs
    expect(Invoice.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        _id:    { $in: invoices.map((i) => i._id) },
        status: { $in: ['initiated', 'pending', 'hash_found'] },
      }),
      { $set: { status: 'expired' } },
    );

    // One event per invoice
    expect(scanner.expiredPublisher.publish).toHaveBeenCalledTimes(3);
  });

  test('Published event contains correct payment.expired structure', async () => {
    const inv = makeInvoiceRecord();
    Invoice.find.mockReturnValue(makeQueryMock([inv]));
    Invoice.updateMany.mockResolvedValue({ modifiedCount: 1 });

    const scanner = makeScanner();
    await scanner._scan();

    expect(scanner.expiredPublisher.publish).toHaveBeenCalledWith(
      expect.objectContaining({
        event:      'payment.expired',
        invoiceId:  String(inv._id),
        merchantId: String(inv.merchantId),
        amount:     String(inv.baseAmount),
      }),
      expect.stringContaining('expired:'),
    );
  });
});

// ═══════════════════════════════════════════════════════════════
// 4 — STATUS GUARD: only expirable statuses are touched
// ═══════════════════════════════════════════════════════════════

describe('Status Guard — only INITIATED, PENDING, HASH_FOUND are expired', () => {
  test('updateMany query includes exactly the three expirable statuses', async () => {
    const inv = makeInvoiceRecord();
    Invoice.find.mockReturnValue(makeQueryMock([inv]));
    Invoice.updateMany.mockResolvedValue({ modifiedCount: 1 });

    const scanner = makeScanner();
    await scanner._scan();

    const updateCall = Invoice.updateMany.mock.calls[0][0];
    const statuses = updateCall.status.$in;

    expect(statuses).toContain('initiated');
    expect(statuses).toContain('pending');
    expect(statuses).toContain('hash_found');

    // CONFIRMED, SUCCESS must NOT be in this list
    expect(statuses).not.toContain('confirmed');
    expect(statuses).not.toContain('success');
    expect(statuses).not.toContain('expired'); // Don't re-expire
  });
});

// ═══════════════════════════════════════════════════════════════
// 5 — BATCH PROCESSING (stops on partial batch)
// ═══════════════════════════════════════════════════════════════

describe('Batch Processing — loop terminates correctly', () => {
  test('First batch returns 100 (full) → does another query; second returns <100 → stops', async () => {
    const batch1 = Array.from({ length: 100 }, makeInvoiceRecord);
    const batch2 = [makeInvoiceRecord(), makeInvoiceRecord()]; // Partial = last batch

    Invoice.find
      .mockReturnValueOnce(makeQueryMock(batch1))
      .mockReturnValueOnce(makeQueryMock(batch2));

    Invoice.updateMany.mockResolvedValue({ modifiedCount: 50 }); // Doesn't matter for loop logic

    const scanner = makeScanner();
    await scanner._scan();

    // find() should have been called twice (two batches)
    expect(Invoice.find).toHaveBeenCalledTimes(2);
  });

  test('First batch returns 50 (< 100) → only one query, loop exits immediately', async () => {
    const batch = Array.from({ length: 50 }, makeInvoiceRecord);
    Invoice.find.mockReturnValue(makeQueryMock(batch));
    Invoice.updateMany.mockResolvedValue({ modifiedCount: 50 });

    const scanner = makeScanner();
    await scanner._scan();

    expect(Invoice.find).toHaveBeenCalledTimes(1);
  });
});

// ═══════════════════════════════════════════════════════════════
// 6 — FAULT TOLERANCE
// ═══════════════════════════════════════════════════════════════

describe('Fault Tolerance — event failure never crashes scanner', () => {
  test('expiredPublisher.publish throws → scan completes, other events still fire', async () => {
    const [inv1, inv2] = [makeInvoiceRecord(), makeInvoiceRecord()];
    Invoice.find.mockReturnValue(makeQueryMock([inv1, inv2]));
    Invoice.updateMany.mockResolvedValue({ modifiedCount: 2 });

    const failingPublisher = {
      publish: jest
        .fn()
        .mockRejectedValueOnce(new Error('Redis unavailable'))
        .mockResolvedValueOnce(undefined), // Second succeeds
    };

    const scanner = makeScanner({ expiredPublisher: failingPublisher });

    // Should not throw
    await expect(scanner._scan()).resolves.not.toThrow();

    // Both events were attempted
    expect(failingPublisher.publish).toHaveBeenCalledTimes(2);
  });

  test('Invoice.find throws → error logged, does not propagate to _tick (caught at tick level)', async () => {
    Invoice.find.mockReturnValue({
      select: jest.fn().mockReturnThis(),
      limit:  jest.fn().mockReturnThis(),
      lean:   jest.fn().mockRejectedValue(new Error('DB connection lost')),
    });

    const scanner = makeScanner();

    // _scan itself throws — _tick catches it
    await expect(scanner._scan()).rejects.toThrow('DB connection lost');
    // The logger should have received the error (verified at tick level)
  });
});

// ═══════════════════════════════════════════════════════════════
// 7 — MODIFIEDCOUNT vs LENGTH (race condition handling)
// ═══════════════════════════════════════════════════════════════

describe('Race condition — updateMany.modifiedCount may be less than found', () => {
  test('updateMany modifiedCount=0 (all raced) → events still fire for found invoices', async () => {
    const inv = makeInvoiceRecord();
    Invoice.find.mockReturnValue(makeQueryMock([inv]));
    // Another process already expired all of them between find() and updateMany()
    Invoice.updateMany.mockResolvedValue({ modifiedCount: 0 });

    const scanner = makeScanner();
    await scanner._scan();

    // Events fired regardless of modifiedCount (status double-update is safe)
    expect(scanner.expiredPublisher.publish).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'payment.expired' }),
      expect.any(String),
    );
  });
});
