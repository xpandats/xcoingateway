'use strict';

/**
 * Matching Engine Test Suite — Banking Grade.
 *
 * Tests the heart of the payment system: engine.js
 *
 * All external dependencies (DB, mongoose sessions, fraud engine,
 * publishers) are mocked so these are true fast unit tests.
 */

// ─── Mongoose session mock ────────────────────────────────────────────────────
const mockSession = {
  withTransaction: jest.fn((fn) => fn()),
  endSession:      jest.fn().mockResolvedValue(undefined),
};

jest.mock('mongoose', () => ({
  startSession: jest.fn().mockResolvedValue(mockSession),
  Types: { ObjectId: String },
}));

jest.mock('@xcg/database', () => ({
  Invoice:     {
    findOne:           jest.fn(),
    findOneAndUpdate:  jest.fn(),
    findByIdAndUpdate: jest.fn(),
  },
  Transaction: {
    findOne:          jest.fn(),
    findOneAndUpdate: jest.fn(),
    create:           jest.fn(),
  },
  LedgerEntry: {
    aggregate: jest.fn(),
    create:    jest.fn(),
  },
}));

const moneyMock = {
  round:    (val, dp) => parseFloat(Number(val).toFixed(dp)),
  add:      (a, b)   => parseFloat((+a + +b).toFixed(8)),
  subtract: (a, b)   => parseFloat((+a - +b).toFixed(8)),
};

jest.mock('@xcg/common', () => ({
  money: moneyMock,
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
      CANCELLED:  'cancelled',
      UNDERPAID:  'underpaid',
      OVERPAID:   'overpaid',
    },
    TX_STATUS: {
      DETECTED:  'detected',
      MATCHED:   'matched',
      CONFIRMED: 'confirmed',
      UNMATCHED: 'unmatched',
    },
  },
}));

const mockFraudCheck = jest.fn().mockResolvedValue({ blocked: false, flagged: false });
jest.mock('@xcg/common/src/fraudEngine', () =>
  jest.fn().mockImplementation(() => ({
    checkIncomingTransaction: mockFraudCheck,
  })),
);

// ─── Imports ──────────────────────────────────────────────────────────────────
const { Invoice, Transaction, LedgerEntry } = require('@xcg/database');
const MatchingEngine = require('../src/engine');

// ─── Mock Chain Helpers ───────────────────────────────────────────────────────
// Mongoose queries are chained:  .findOne({}).select('x').lean() → Promise
// To mock this correctly the return value must support the full chain.

/** Builds a mock chain for Transaction.findOne().select().lean() */
function txFindOneChain(result) {
  return {
    select: jest.fn().mockReturnValue({
      lean: jest.fn().mockResolvedValue(result),
    }),
  };
}

/** Builds a mock chain for Invoice.findOne().lean() */
function invoiceFindOneChain(result) {
  return {
    lean: jest.fn().mockResolvedValue(result),
  };
}

// ─── Object Builders ─────────────────────────────────────────────────────────
function makeEngine(overrides = {}) {
  return new MatchingEngine({
    minConfirmations:    19,
    platformFeeRate:     0.001,
    confirmedPublisher:  { publish: jest.fn().mockResolvedValue(undefined) },
    alertPublisher:      { publish: jest.fn().mockResolvedValue(undefined) },
    withdrawalPublisher: { publish: jest.fn().mockResolvedValue(undefined) },
    logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
    ...overrides,
  });
}

function makeTx(overrides = {}) {
  return {
    txHash:        'a'.repeat(64),
    blockNum:      60000000,
    confirmations: 5,
    fromAddress:   'TFromAddress0000000000000000000000',
    toAddress:     'TWalletAddress000000000000000000000',
    amount:        '100.000347',
    tokenContract: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',
    tokenSymbol:   'USDT',
    network:       'tron',
    timestamp:     Math.floor(Date.now() / 1000),
    detectedAt:    Date.now(),
    ...overrides,
  };
}

function makeInvoice(overrides = {}) {
  return {
    _id:           'invoice_id_001',
    invoiceId:     'inv_001',
    merchantId:    'merchant_001',
    walletAddress: 'TWalletAddress000000000000000000000',
    uniqueAmount:  100.000347,
    baseAmount:    100,
    callbackUrl:   'https://merchant.example.com/webhook',
    status:        'pending',
    ...overrides,
  };
}

// ─── Global beforeEach ────────────────────────────────────────────────────────
beforeEach(() => {
  jest.clearAllMocks();

  // Restore session behavior
  mockSession.withTransaction.mockImplementation((fn) => fn());
  mockSession.endSession.mockResolvedValue(undefined);

  // Safe defaults — return null (no existing record)
  Transaction.findOne.mockReturnValue(txFindOneChain(null));
  Invoice.findOne.mockReturnValue(invoiceFindOneChain(null));
  Invoice.findOneAndUpdate.mockResolvedValue(null);
  Invoice.findByIdAndUpdate.mockResolvedValue({});
  Transaction.findOneAndUpdate.mockResolvedValue({});
  Transaction.create.mockResolvedValue([{}]);
  LedgerEntry.create.mockResolvedValue([{}, {}, {}]);

  // LedgerEntry.aggregate().session() → empty (balance=0, starting fresh)
  LedgerEntry.aggregate.mockReturnValue({
    session: jest.fn().mockResolvedValue([]),
  });

  mockFraudCheck.mockResolvedValue({ blocked: false, flagged: false });
});

// ═══════════════════════════════════════════════════════════════
// 1 — IDEMPOTENCY
// ═══════════════════════════════════════════════════════════════
describe('Idempotency — duplicate TX hash', () => {
  test('TX already DETECTED in DB → early return, no invoice lookup', async () => {
    Transaction.findOne.mockReturnValue(txFindOneChain({ status: 'detected' }));

    const engine = makeEngine();
    await engine.handle(makeTx(), 'idem-001');

    expect(Invoice.findOne).not.toHaveBeenCalled();
    expect(Transaction.create).not.toHaveBeenCalled();
    expect(LedgerEntry.create).not.toHaveBeenCalled();
  });

  test('TX already CONFIRMED in DB → still ignored (no double credit)', async () => {
    Transaction.findOne.mockReturnValue(txFindOneChain({ status: 'confirmed' }));

    const engine = makeEngine();
    await engine.handle(makeTx(), 'idem-002');

    expect(Invoice.findOne).not.toHaveBeenCalled();
    expect(LedgerEntry.create).not.toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// 2 — CONTRACT WHITELIST
// ═══════════════════════════════════════════════════════════════
describe('Contract Whitelist — USDT-only enforcement', () => {
  test('Unknown contract → rejected before invoice lookup', async () => {
    const engine = makeEngine();
    await engine.handle(makeTx({ tokenContract: 'TFakeCoinXXXXXXXXXXXXXXXXXXXXXXXXXX' }), 'cw-001');

    expect(Invoice.findOne).not.toHaveBeenCalled();
    expect(Transaction.findOneAndUpdate).toHaveBeenCalled(); // _recordFailed
  });

  test('Testnet USDT contract (TXLAQ63...) → accepted, reaches invoice lookup', async () => {
    // No invoice match — that's fine, just checking it passes the contract filter
    Invoice.findOne.mockReturnValue(invoiceFindOneChain(null));

    const engine = makeEngine();
    await engine.handle(makeTx({ tokenContract: 'TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj' }), 'cw-002');

    expect(Invoice.findOne).toHaveBeenCalled();
  });

  test('ETH contract address → rejected', async () => {
    const engine = makeEngine();
    await engine.handle(makeTx({ tokenContract: '0xdAC17F958D2ee523a2206206994597C13D831ec7' }), 'cw-003');

    expect(Invoice.findOne).not.toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// 3 — TOKEN SYMBOL
// ═══════════════════════════════════════════════════════════════
describe('Token Symbol — USDT symbol enforced', () => {
  test('tokenSymbol = USDC → rejected', async () => {
    const engine = makeEngine();
    await engine.handle(makeTx({ tokenSymbol: 'USDC' }), 'sym-001');

    expect(Invoice.findOne).not.toHaveBeenCalled();
  });

  test('tokenSymbol = TRX → rejected', async () => {
    const engine = makeEngine();
    await engine.handle(makeTx({ tokenSymbol: 'TRX' }), 'sym-002');

    expect(Invoice.findOne).not.toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// 4 — FRAUD ENGINE
// ═══════════════════════════════════════════════════════════════
describe('Fraud Engine — blocking and flagging', () => {
  beforeEach(() => {
    Invoice.findOne.mockReturnValue(invoiceFindOneChain(makeInvoice()));
  });

  test('Fraud BLOCKED → _recordFailed, no invoice update', async () => {
    mockFraudCheck.mockResolvedValue({
      blocked: true, flagged: false,
      reason: 'OFAC', eventType: 'ofac_hit', riskScore: 100,
    });

    const engine = makeEngine();
    await engine.handle(makeTx(), 'fraud-001');

    expect(Transaction.findOneAndUpdate).toHaveBeenCalled();
    expect(Invoice.findOneAndUpdate).not.toHaveBeenCalled();
  });

  test('Fraud FLAGGED (not blocked) → processing continues', async () => {
    mockFraudCheck.mockResolvedValue({
      blocked: false, flagged: true, reason: 'Velocity', eventType: 'velocity', riskScore: 60,
    });
    Invoice.findOneAndUpdate.mockResolvedValue(makeInvoice({ status: 'hash_found' }));

    const engine = makeEngine();
    await engine.handle(makeTx({ confirmations: 5 }), 'fraud-002');

    // Invoice WAS updated (continued despite flag)
    expect(Invoice.findOneAndUpdate).toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// 5 — DETECTION PATH (Phase 1 — HASH_FOUND)
// ═══════════════════════════════════════════════════════════════
describe('Detection Path — HASH_FOUND, Phase 1 (< minConfirmations)', () => {
  beforeEach(() => {
    Invoice.findOne.mockReturnValue(invoiceFindOneChain(makeInvoice()));
    Invoice.findOneAndUpdate.mockResolvedValue(makeInvoice({ status: 'hash_found' }));
  });

  test('TX with 5 confs → invoice set HASH_FOUND, TX created as DETECTED', async () => {
    const engine = makeEngine();
    await engine.handle(makeTx({ confirmations: 5 }), 'det-001');

    expect(Invoice.findOneAndUpdate).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'pending' }),
      expect.objectContaining({ $set: expect.objectContaining({ status: 'hash_found' }) }),
      expect.any(Object),
    );
    expect(Transaction.create).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({ status: 'detected', txHash: 'a'.repeat(64) }),
      ]),
      expect.any(Object),
    );
  });

  test('TX with 0 confs → still detected (detection is conf-agnostic)', async () => {
    const engine = makeEngine();
    await engine.handle(makeTx({ confirmations: 0 }), 'det-002');

    expect(Invoice.findOneAndUpdate).toHaveBeenCalled();
    expect(Transaction.create).toHaveBeenCalled();
  });

  test('payment.detected event published after detection', async () => {
    const engine = makeEngine();
    await engine.handle(makeTx(), 'det-003');

    expect(engine.confirmedPublisher.publish).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'payment.detected' }),
      expect.stringContaining('detected:'),
    );
  });

  test('Race: invoice already claimed (findOneAndUpdate → null) → TX NOT created', async () => {
    Invoice.findOneAndUpdate.mockResolvedValue(null); // Race lost

    const engine = makeEngine();
    await engine.handle(makeTx(), 'race-001');

    expect(Transaction.create).not.toHaveBeenCalled();
  });

  test('Session always ended even in race condition', async () => {
    Invoice.findOneAndUpdate.mockResolvedValue(null);

    const engine = makeEngine();
    await engine.handle(makeTx(), 'race-002');

    expect(mockSession.endSession).toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// 6 — FAST PATH (already ≥ minConfirmations at detection time)
// ═══════════════════════════════════════════════════════════════
describe('Fast Path — TX already ≥19 confirmations → direct _confirmPayment', () => {
  beforeEach(() => {
    Invoice.findOne.mockReturnValue(invoiceFindOneChain(makeInvoice()));
    Invoice.findOneAndUpdate.mockResolvedValue(makeInvoice({ status: 'confirmed' }));
    Transaction.create.mockResolvedValue([{}]);
    Transaction.findOneAndUpdate.mockResolvedValue({});
    LedgerEntry.aggregate.mockReturnValue({ session: jest.fn().mockResolvedValue([]) });
    LedgerEntry.create.mockResolvedValue([{}, {}, {}]);
  });

  test('19 confirmations → ledger entries created (skips Phase 1)', async () => {
    const engine = makeEngine({ minConfirmations: 19 });
    await engine.handle(makeTx({ confirmations: 19 }), 'fast-001');

    expect(LedgerEntry.create).toHaveBeenCalled();
  });

  test('50 confirmations → same fast path', async () => {
    const engine = makeEngine({ minConfirmations: 19 });
    await engine.handle(makeTx({ confirmations: 50 }), 'fast-002');

    expect(LedgerEntry.create).toHaveBeenCalled();
  });

  test('Fast path: Transaction.create called with MATCHED, then findOneAndUpdate → CONFIRMED', async () => {
    const engine = makeEngine({ minConfirmations: 19 });
    await engine.handle(makeTx({ confirmations: 19 }), 'fast-003');

    expect(Transaction.create).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({ status: 'matched' }),
      ]),
    );
    expect(Transaction.findOneAndUpdate).toHaveBeenCalledWith(
      expect.objectContaining({ txHash: 'a'.repeat(64) }),
      expect.objectContaining({ $set: expect.objectContaining({ status: 'confirmed' }) }),
      expect.any(Object),
    );
  });

  test('Withdrawal eligibility queued after confirmation', async () => {
    const engine = makeEngine({ minConfirmations: 19 });
    await engine.handle(makeTx({ confirmations: 19 }), 'fast-004');

    expect(engine.withdrawalPublisher.publish).toHaveBeenCalledWith(
      expect.objectContaining({ merchantId: 'merchant_001' }),
      expect.stringContaining('withdrawal:'),
    );
  });
});

// ═══════════════════════════════════════════════════════════════
// 7 — LEDGER DOUBLE-ENTRY ACCOUNTING
// ═══════════════════════════════════════════════════════════════
describe('Ledger Double-Entry Accounting (0.1% fee)', () => {
  const received = 100.000347;
  const feeRate  = 0.001;

  beforeEach(() => {
    Invoice.findOne.mockReturnValue(invoiceFindOneChain(makeInvoice({ uniqueAmount: received })));
    Invoice.findOneAndUpdate.mockResolvedValue(makeInvoice({ status: 'confirmed' }));
    Transaction.create.mockResolvedValue([{}]);
    Transaction.findOneAndUpdate.mockResolvedValue({});
    LedgerEntry.aggregate.mockReturnValue({ session: jest.fn().mockResolvedValue([]) });
    LedgerEntry.create.mockResolvedValue([{}, {}, {}]);
  });

  // NOTE: minConfirmations:0 is falsy → engine coerces to 19 via `minConfirmations || 19`.
  // Use confirmations:19 (≥ default threshold) to trigger the fast-path → _confirmPayment.

  test('Three entries: hot_wallet_incoming(D) + merchant_receivable(C) + platform_fee(C)', async () => {
    const engine = makeEngine({ platformFeeRate: feeRate });
    await engine.handle(makeTx({ amount: String(received), confirmations: 19 }), 'led-001');

    const entries = LedgerEntry.create.mock.calls[0][0];
    expect(entries).toHaveLength(3);

    const debit  = entries.find((e) => e.account === 'hot_wallet_incoming');
    const credit = entries.find((e) => e.account === 'merchant_receivable');
    const fee    = entries.find((e) => e.account === 'platform_fee');

    expect(debit).toBeDefined();
    expect(credit).toBeDefined();
    expect(fee).toBeDefined();

    expect(debit.type).toBe('debit');
    expect(credit.type).toBe('credit');
    expect(fee.type).toBe('credit');
  });

  test('Double-entry rule: debit amount = credit + fee', async () => {
    const engine = makeEngine({ platformFeeRate: feeRate });
    await engine.handle(makeTx({ amount: String(received), confirmations: 19 }), 'led-002');

    const entries     = LedgerEntry.create.mock.calls[0][0];
    const debit       = entries.find((e) => e.account === 'hot_wallet_incoming');
    const credit      = entries.find((e) => e.account === 'merchant_receivable');
    const fee         = entries.find((e) => e.account === 'platform_fee');
    const expectedFee = parseFloat((received * feeRate).toFixed(6));
    const expectedNet = parseFloat((received - expectedFee).toFixed(6));

    expect(debit.amount).toBeCloseTo(received, 5);
    expect(credit.amount).toBeCloseTo(expectedNet, 5);
    expect(fee.amount).toBeCloseTo(expectedFee, 5);
    expect(debit.amount).toBeCloseTo(credit.amount + fee.amount, 4);
  });

  test('Idempotency keys prevent duplicate ledger entries', async () => {
    const engine  = makeEngine({ platformFeeRate: feeRate });
    const txHash  = 'a'.repeat(64);
    await engine.handle(makeTx({ amount: String(received), confirmations: 19 }), 'led-003');

    const entries = LedgerEntry.create.mock.calls[0][0];
    expect(entries[0].idempotencyKey).toBe(`ledger:incoming:${txHash}`);
    expect(entries[1].idempotencyKey).toBe(`ledger:recv:${txHash}`);
    expect(entries[2].idempotencyKey).toBe(`ledger:fee:${txHash}`);
  });

  test('Cross-reference: debit.counterpartEntryId = credit.entryId', async () => {
    const engine = makeEngine({ platformFeeRate: feeRate });
    await engine.handle(makeTx({ amount: String(received), confirmations: 19 }), 'led-004');

    const entries = LedgerEntry.create.mock.calls[0][0];
    const debit   = entries.find((e) => e.account === 'hot_wallet_incoming');
    const credit  = entries.find((e) => e.account === 'merchant_receivable');

    expect(debit.counterpartEntryId).toBe(credit.entryId);
    expect(credit.counterpartEntryId).toBe(debit.entryId);
  });
});

// ═══════════════════════════════════════════════════════════════
// 8 — NO MATCH FLOWS
// ═══════════════════════════════════════════════════════════════
describe('No Match — _handleNoMatch flows', () => {
  beforeEach(() => {
    // Primary invoice query → no match
    Invoice.findOne.mockReturnValue(invoiceFindOneChain(null));
    Invoice.findByIdAndUpdate.mockResolvedValue({});
  });

  test('No invoice found at all → TX recorded as no_invoice_match', async () => {
    // All subsequent findOne calls also return null
    Invoice.findOne.mockReturnValue(invoiceFindOneChain(null));

    const engine = makeEngine();
    await engine.handle(makeTx(), 'nm-001');

    expect(Transaction.findOneAndUpdate).toHaveBeenCalledWith(
      expect.objectContaining({ txHash: 'a'.repeat(64) }),
      expect.objectContaining({
        $setOnInsert: expect.objectContaining({ matchResult: 'no_invoice_match' }),
      }),
      expect.any(Object),
    );
  });

  test('Duplicate payment (already CONFIRMED invoice) → duplicate_payment + alert', async () => {
    Invoice.findOne
      .mockReturnValueOnce(invoiceFindOneChain(null))                        // main match
      .mockReturnValueOnce(invoiceFindOneChain(makeInvoice({ status: 'confirmed' }))) // duplicate
      .mockReturnValue(invoiceFindOneChain(null));

    const engine    = makeEngine();
    const alertPub  = engine.alertPublisher;
    await engine.handle(makeTx(), 'nm-002');

    expect(Transaction.findOneAndUpdate).toHaveBeenCalledWith(
      expect.any(Object),
      expect.objectContaining({
        $setOnInsert: expect.objectContaining({ matchResult: 'duplicate_payment' }),
      }),
      expect.any(Object),
    );
    expect(alertPub.publish).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'duplicate_payment' }),
      expect.any(String),
    );
  });

  test('Late payment on expired invoice → late_payment + alert', async () => {
    Invoice.findOne
      .mockReturnValueOnce(invoiceFindOneChain(null))                        // main match
      .mockReturnValueOnce(invoiceFindOneChain(null))                        // no duplicate
      .mockReturnValueOnce(invoiceFindOneChain(makeInvoice({ status: 'expired' }))) // late
      .mockReturnValue(invoiceFindOneChain(null));

    const engine   = makeEngine();
    const alertPub = engine.alertPublisher;
    await engine.handle(makeTx(), 'nm-003');

    expect(Transaction.findOneAndUpdate).toHaveBeenCalledWith(
      expect.any(Object),
      expect.objectContaining({
        $setOnInsert: expect.objectContaining({ matchResult: 'late_payment' }),
      }),
      expect.any(Object),
    );
    expect(alertPub.publish).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'late_payment' }),
      expect.any(String),
    );
  });

  test('Underpayment → invoice set UNDERPAID + alert', async () => {
    const underpaid = makeInvoice({ status: 'pending', uniqueAmount: 150 });
    Invoice.findOne
      .mockReturnValueOnce(invoiceFindOneChain(null))     // main match
      .mockReturnValueOnce(invoiceFindOneChain(null))     // no duplicate
      .mockReturnValueOnce(invoiceFindOneChain(null))     // no late
      .mockReturnValueOnce(invoiceFindOneChain(underpaid)) // underpayment match
      .mockReturnValue(invoiceFindOneChain(null));

    const engine   = makeEngine();
    const alertPub = engine.alertPublisher;
    await engine.handle(makeTx({ amount: '100.000347' }), 'nm-004');

    expect(Invoice.findByIdAndUpdate).toHaveBeenCalledWith(
      underpaid._id,
      { $set: { status: 'underpaid' } },
    );
    expect(alertPub.publish).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'underpayment' }),
      expect.any(String),
    );
  });

  test('Overpayment → confirmed at invoice amount + alert', async () => {
    const overpaid = makeInvoice({ status: 'pending', uniqueAmount: 90 });
    Invoice.findOne
      .mockReturnValueOnce(invoiceFindOneChain(null))
      .mockReturnValueOnce(invoiceFindOneChain(null))
      .mockReturnValueOnce(invoiceFindOneChain(null))
      .mockReturnValueOnce(invoiceFindOneChain(null))
      .mockReturnValueOnce(invoiceFindOneChain(overpaid));

    // _confirmPayment needs these
    Invoice.findOneAndUpdate.mockResolvedValue(overpaid);
    Transaction.findOneAndUpdate.mockResolvedValue({});
    LedgerEntry.aggregate.mockReturnValue({ session: jest.fn().mockResolvedValue([]) });
    LedgerEntry.create.mockResolvedValue([{}, {}, {}]);

    const engine   = makeEngine({ minConfirmations: 0 });
    const alertPub = engine.alertPublisher;
    await engine.handle(makeTx({ amount: '100.000347', confirmations: 0 }), 'nm-005');

    expect(alertPub.publish).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'overpayment' }),
      expect.any(String),
    );
    expect(LedgerEntry.create).toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// 9 — PUBLISHERS
// ═══════════════════════════════════════════════════════════════
describe('Publishers — confirm path fires correct events', () => {
  beforeEach(() => {
    Invoice.findOne.mockReturnValue(invoiceFindOneChain(makeInvoice()));
    Invoice.findOneAndUpdate.mockResolvedValue(makeInvoice({ status: 'confirmed' }));
    Transaction.create.mockResolvedValue([{}]);
    Transaction.findOneAndUpdate.mockResolvedValue({});
    LedgerEntry.aggregate.mockReturnValue({ session: jest.fn().mockResolvedValue([]) });
    LedgerEntry.create.mockResolvedValue([{}, {}, {}]);
  });

  test('payment.confirmed event published', async () => {
    const engine = makeEngine();
    await engine.handle(makeTx({ confirmations: 19 }), 'pub-001');

    expect(engine.confirmedPublisher.publish).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'payment.confirmed' }),
      expect.stringContaining('confirmed:'),
    );
  });

  test('Withdrawal eligibility published', async () => {
    const engine = makeEngine();
    await engine.handle(makeTx({ confirmations: 19 }), 'pub-002');

    expect(engine.withdrawalPublisher.publish).toHaveBeenCalledWith(
      expect.objectContaining({ merchantId: 'merchant_001' }),
      expect.stringContaining('withdrawal:'),
    );
  });
});

// ═══════════════════════════════════════════════════════════════
// 10 — FAULT TOLERANCE
// ═══════════════════════════════════════════════════════════════
describe('Fault Tolerance — alert failures never crash engine', () => {
  test('alertPublisher.publish throws → engine does not propagate the error', async () => {
    Invoice.findOne.mockReturnValue(invoiceFindOneChain(null)); // → _handleNoMatch → no match

    const alertPub = { publish: jest.fn().mockRejectedValue(new Error('Redis down')) };
    const engine   = makeEngine({ alertPublisher: alertPub });

    await expect(engine.handle(makeTx(), 'fault-001')).resolves.not.toThrow();
  });
});
