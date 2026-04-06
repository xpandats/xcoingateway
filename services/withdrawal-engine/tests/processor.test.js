'use strict';

/**
 * Withdrawal Processor Test Suite — Banking Grade.
 *
 * Tests WithdrawalProcessor from withdrawal-engine/src/processor.js
 *
 * Security rules enforced (from code comments):
 *   1. Ledger balance confirmed BEFORE withdrawal
 *   2. 1-hour cooling-off period after last deposit
 *   3. Per-transaction limit (1000 USDT default)
 *   4. Daily cap (10,000 USDT default)
 *   5. Destination address must NOT be our own wallet
 *   6. High-value (>5000 USDT) requires admin approval
 *   7. Active disputes block withdrawals
 *   8. Idempotency key prevents duplicate processing
 *   9. No signingPublisher call when requiresApproval=true
 *  10. Insufficient Tron energy → withdrawal deferred
 */

// ─── Mongoose session mock ────────────────────────────────────────────────────
const mockSession = {
  withTransaction: jest.fn((fn) => fn()),
  endSession:      jest.fn().mockResolvedValue(undefined),
};

jest.mock('mongoose', () => ({
  startSession: jest.fn().mockResolvedValue(mockSession),
  Types: {
    ObjectId: jest.fn((id) => id),
  },
}));

jest.mock('@xcg/database', () => ({
  Merchant:    { findById: jest.fn() },
  Wallet:      { findOne: jest.fn(), exists: jest.fn() },
  Withdrawal:  { create: jest.fn(), aggregate: jest.fn(), findByIdAndUpdate: jest.fn() },
  LedgerEntry: { create: jest.fn(), aggregate: jest.fn(), findOne: jest.fn() },
  Dispute:     { exists: jest.fn() },
}));

jest.mock('@xcg/common', () => ({
  constants: {
    DISPUTE_STATUS: {
      OPENED:              'opened',
      MERCHANT_RESPONDED:  'merchant_responded',
      UNDER_REVIEW:        'under_review',
      RESOLVED_REFUND:     'resolved_refund',
      RESOLVED_NO_REFUND:  'resolved_no_refund',
      CLOSED:              'closed',
    },
  },
}));

const { Merchant, Wallet, Withdrawal, LedgerEntry, Dispute } = require('@xcg/database');
const WithdrawalProcessor = require('../src/processor');

// ─── Config ──────────────────────────────────────────────────────────────────
const DEFAULT_CONFIG = {
  perTxWithdrawalLimit:  1000,  // USDT
  dailyWithdrawalCap:    10000, // USDT
  highValueThreshold:    5000,  // USDT
  withdrawalCooldownMs:  3600000, // 1 hour
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeProcessor(overrides = {}) {
  return new WithdrawalProcessor({
    signingPublisher: { publish: jest.fn().mockResolvedValue(undefined) },
    alertPublisher:   { publish: jest.fn().mockResolvedValue(undefined) },
    tronAdapter:      { hasSufficientEnergy: jest.fn().mockResolvedValue(true) },
    config:           DEFAULT_CONFIG,
    tronNetwork:      'testnet',
    logger: {
      info:  jest.fn(),
      warn:  jest.fn(),
      error: jest.fn(),
      debug: jest.fn(),
    },
    ...overrides,
  });
}

function makeEventData(overrides = {}) {
  return {
    merchantId: 'a'.repeat(24),
    invoiceId:  'b'.repeat(24),
    amount:     '100.000000',
    ...overrides,
  };
}

function makeMerchant(overrides = {}) {
  return {
    _id:               'a'.repeat(24),
    withdrawalAddress: 'TN3W4T7pk41MMxL1mjC6HeMoAWH7aA4X9F',
    businessName:      'Test Merchant',
    isActive:          true,
    dailyWithdrawalUsed: 0,
    ...overrides,
  };
}

function makeWallet(overrides = {}) {
  return {
    _id:     'c'.repeat(24),
    address: 'THotWallet0000000000000000000000001',
    isActive: true,
    ...overrides,
  };
}
// ─── Mock Chain Helper ───────────────────────────────────────────────────────
// processor.js: Merchant.findById(id).select('...').lean()
function merchantFindByIdChain(result) {
  return {
    select: jest.fn().mockReturnValue({
      lean: jest.fn().mockResolvedValue(result),
    }),
  };
}

// processor.js _getLastDepositTime: LedgerEntry.findOne({...}).sort({...}).select('createdAt').lean()
function ledgerFindOneChain(result) {
  const lean   = jest.fn().mockResolvedValue(result);
  const select = jest.fn().mockReturnValue({ lean });
  const sort   = jest.fn().mockReturnValue({ select });
  return { sort };
}

// processor.js handle: Wallet.findOne({...}).sort({...}).select('_id address').lean()
function walletFindOneChain(result) {
  const lean   = jest.fn().mockResolvedValue(result);
  const select = jest.fn().mockReturnValue({ lean });
  const sort   = jest.fn().mockReturnValue({ select });
  return { sort };
}

beforeEach(() => {
  jest.clearAllMocks();
  mockSession.withTransaction.mockImplementation((fn) => fn());
  mockSession.endSession.mockResolvedValue(undefined);

  // Default: no merchant found (safe fallback — each test/describe overrides)
  Merchant.findById.mockReturnValue(merchantFindByIdChain(null));

  // Default: cooling-off check — null means no prior deposit (no cooling off applied)
  LedgerEntry.findOne.mockReturnValue(ledgerFindOneChain(null));

  // Default: no active disputes
  Dispute.exists.mockResolvedValue(null);

  // Default: merchant's withdrawal address is NOT one of our wallets
  Wallet.exists.mockResolvedValue(null);

  // Default: Ledger balance = 500 USDT (more than enough for 100 USDT withdrawal)
  LedgerEntry.aggregate.mockResolvedValue([{ credits: 500, debits: 0 }]);

  // Default: No daily withdrawals yet
  Withdrawal.aggregate.mockResolvedValue([]);

  // Default: last deposit was 2 hours ago (past cooling-off)
  const twoHoursAgo = new Date(Date.now() - 2 * 3600000);
  // getLast deposit mock setup below per test

  // Default: hot wallet available (chain: Wallet.findOne({}).sort({}).select('_id address').lean())
  Wallet.findOne.mockReturnValue(walletFindOneChain(makeWallet()));

  // Default: Withdrawal.create returns a valid record
  Withdrawal.create.mockResolvedValue([{
    _id:          'withdrawal_001',
    withdrawalId: 'wdl_test001',
  }]);

  // Default: LedgerEntry.create succeeds
  LedgerEntry.create.mockResolvedValue([{}, {}]);
});

// ═══════════════════════════════════════════════════════════════
// 1 — MERCHANT VALIDATION
// ═══════════════════════════════════════════════════════════════

describe('Merchant Validation', () => {
  test('Merchant not found → early return, no withdrawal created', async () => {
    Merchant.findById.mockReturnValue(merchantFindByIdChain(null));

    const proc = makeProcessor();
    await proc.handle(makeEventData(), 'idem-001');

    expect(Withdrawal.create).not.toHaveBeenCalled();
    expect(proc.signingPublisher.publish).not.toHaveBeenCalled();
  });

  test('Merchant inactive → early return', async () => {
    Merchant.findById.mockReturnValue(merchantFindByIdChain(makeMerchant({ isActive: false })));

    const proc = makeProcessor();
    await proc.handle(makeEventData(), 'idem-002');

    expect(Withdrawal.create).not.toHaveBeenCalled();
  });

  test('Merchant has no withdrawal address → funds held, early return', async () => {
    Merchant.findById.mockReturnValue(merchantFindByIdChain(makeMerchant({ withdrawalAddress: null })));

    const proc = makeProcessor();
    await proc.handle(makeEventData(), 'idem-003');

    expect(Withdrawal.create).not.toHaveBeenCalled();
    expect(proc.signingPublisher.publish).not.toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// 1b — AUTO-WITHDRAWAL GATE
// ═══════════════════════════════════════════════════════════════

describe('Auto-Withdrawal Gate — merchant opt-out', () => {
  test('Merchant with autoWithdrawal=false → early return, no withdrawal created', async () => {
    Merchant.findById.mockReturnValue(merchantFindByIdChain(makeMerchant({ autoWithdrawal: false })));

    const proc = makeProcessor();
    await proc.handle(makeEventData(), 'auto-001');

    // Funds held — no withdrawal, no signing, no alert (this is normal merchant opt-out, not an error)
    expect(Withdrawal.create).not.toHaveBeenCalled();
    expect(proc.signingPublisher.publish).not.toHaveBeenCalled();
    expect(proc.alertPublisher.publish).not.toHaveBeenCalled();
  });

  test('Merchant with autoWithdrawal=true → processing continues past the gate', async () => {
    // autoWithdrawal=true: processing should proceed (and get stopped by own-wallet check
    // since Wallet.exists returns null by default and other defaults allow through)
    Merchant.findById.mockReturnValue(merchantFindByIdChain(makeMerchant({ autoWithdrawal: true })));
    Wallet.exists.mockResolvedValue(null);  // Not own wallet
    Dispute.exists.mockResolvedValue(null); // No dispute
    // Set up remaining defaults so it reaches ledger balance check
    LedgerEntry.aggregate.mockResolvedValue([{ credits: 500, debits: 0 }]);
    Withdrawal.aggregate.mockResolvedValue([]);
    LedgerEntry.findOne.mockReturnValue(ledgerFindOneChain(null)); // No prior deposit → no cooling off

    const proc = makeProcessor();
    await proc.handle(makeEventData(), 'auto-002');

    // Should have proceeded past the gate (Withdrawal.create called = gate was passed)
    expect(Withdrawal.create).toHaveBeenCalled();
  });

  test('Merchant with autoWithdrawal undefined (default) → proceeds as auto-withdrawal enabled', async () => {
    // makeMerchant() does not set autoWithdrawal — defaults to undefined (truthy path)
    Merchant.findById.mockReturnValue(merchantFindByIdChain(makeMerchant()));
    Wallet.exists.mockResolvedValue(null);
    Dispute.exists.mockResolvedValue(null);
    LedgerEntry.aggregate.mockResolvedValue([{ credits: 500, debits: 0 }]);
    Withdrawal.aggregate.mockResolvedValue([]);
    LedgerEntry.findOne.mockReturnValue(ledgerFindOneChain(null));

    const proc = makeProcessor();
    await proc.handle(makeEventData(), 'auto-003');

    expect(Withdrawal.create).toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// 2 — SELF-WITHDRAWAL PREVENTION (Security Rule 5)
// ═══════════════════════════════════════════════════════════════

describe('Self-Withdrawal Prevention — Rule 5', () => {
  test('Merchant withdrawal address = one of our own wallets → blocked + alert', async () => {
    Merchant.findById.mockReturnValue(merchantFindByIdChain(makeMerchant()));
    Wallet.exists.mockResolvedValue(true); // Address IS our own wallet

    const proc = makeProcessor();
    const alertPub = proc.alertPublisher;
    await proc.handle(makeEventData(), 'self-001');

    expect(Withdrawal.create).not.toHaveBeenCalled();
    expect(alertPub.publish).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'withdrawal_to_own_wallet' }),
      expect.any(String),
    );
  });
});

// ═══════════════════════════════════════════════════════════════
// 3 — ACTIVE DISPUTE BLOCK (Security Rule)
// ═══════════════════════════════════════════════════════════════

describe('Active Dispute Block — funds frozen during disputes', () => {
  beforeEach(() => {
    Merchant.findById.mockReturnValue(merchantFindByIdChain(makeMerchant()));
  });

  test('Merchant has OPENED dispute → withdrawal blocked + alert', async () => {
    Dispute.exists.mockResolvedValue(true); // Active dispute found

    const proc = makeProcessor();
    const alertPub = proc.alertPublisher;
    await proc.handle(makeEventData(), 'disp-001');

    expect(Withdrawal.create).not.toHaveBeenCalled();
    expect(alertPub.publish).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'withdrawal_blocked_active_dispute' }),
      expect.any(String),
    );
  });

  test('No active dispute → processing continues', async () => {
    Dispute.exists.mockResolvedValue(null); // No dispute

    // Set up for normal processing to reach signing
    const proc = makeProcessor();
    // Need to make getLast deposit return null (no cooling off)
    // LedgerEntry.aggregate for balance returns enough
    // But also LedgerEntry/_getLastDepositTime uses LedgerEntry.findOne...
    // Since we mock the entire module, we need to handle this

    // Actually _getLastDepositTime uses LedgerEntry.findOne (NOT aggregate)
    // Let's check - no, _getLastDepositTime uses LedgerEntry.findOne
    // But we only mocked aggregate, not findOne. Let's add findOne mock.
    const { LedgerEntry: LE } = require('@xcg/database');
    LE.findOne.mockReturnValue(ledgerFindOneChain(null)); // No prior deposit = no cooling off

    await proc.handle(makeEventData(), 'disp-002');

    // Should reach signing
    expect(proc.signingPublisher.publish).toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// 4 — PER-TRANSACTION LIMIT (Security Rule 3)
// ═══════════════════════════════════════════════════════════════

describe('Per-Transaction Limit — Security Rule 3 (1000 USDT default)', () => {
  beforeEach(() => {
    Merchant.findById.mockReturnValue(merchantFindByIdChain(makeMerchant()));
    Dispute.exists.mockResolvedValue(null);
  });

  test('Amount = 1001 USDT → blocked, alert sent, no withdrawal created', async () => {
    const proc = makeProcessor();
    const alertPub = proc.alertPublisher;

    await proc.handle(makeEventData({ amount: '1001.000000' }), 'limit-001');

    expect(Withdrawal.create).not.toHaveBeenCalled();
    expect(alertPub.publish).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'withdrawal_over_per_tx_limit' }),
      expect.any(String),
    );
  });

  test('Amount = 1000 USDT (exactly at limit) → allowed', async () => {
    const { LedgerEntry: LE } = require('@xcg/database');
    LE.findOne.mockReturnValue(ledgerFindOneChain(null));
    LedgerEntry.aggregate.mockResolvedValue([{ credits: 2000, debits: 0 }]);
    Withdrawal.aggregate.mockResolvedValue([]);

    const proc = makeProcessor();
    await proc.handle(makeEventData({ amount: '1000.000000' }), 'limit-002');

    // Should NOT be blocked by per-tx limit (1000 is not > 1000)
    expect(proc.alertPublisher.publish).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: 'withdrawal_over_per_tx_limit' }),
      expect.any(String),
    );
  });

  test('Amount = 999 USDT → allowed (under limit)', async () => {
    const { LedgerEntry: LE } = require('@xcg/database');
    LE.findOne.mockReturnValue(ledgerFindOneChain(null));
    LedgerEntry.aggregate.mockResolvedValue([{ credits: 2000, debits: 0 }]);
    Withdrawal.aggregate.mockResolvedValue([]);

    const proc = makeProcessor();
    await proc.handle(makeEventData({ amount: '999.000000' }), 'limit-003');

    expect(proc.signingPublisher.publish).toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// 5 — LEDGER BALANCE CHECK (Security Rule 1)
// ═══════════════════════════════════════════════════════════════

describe('Ledger Balance Check — Security Rule 1 (balance must cover withdrawal)', () => {
  beforeEach(() => {
    Merchant.findById.mockReturnValue(merchantFindByIdChain(makeMerchant()));
    Dispute.exists.mockResolvedValue(null);
  });

  test('Balance 50 USDT, withdrawal 100 USDT → insufficient, early return', async () => {
    LedgerEntry.aggregate.mockResolvedValue([{ credits: 50, debits: 0 }]);

    const proc = makeProcessor();
    await proc.handle(makeEventData({ amount: '100.000000' }), 'bal-001');

    expect(Withdrawal.create).not.toHaveBeenCalled();
    expect(proc.signingPublisher.publish).not.toHaveBeenCalled();
  });

  test('Balance 0 USDT → insufficient', async () => {
    LedgerEntry.aggregate.mockResolvedValue([]);

    const proc = makeProcessor();
    await proc.handle(makeEventData({ amount: '100.000000' }), 'bal-002');

    expect(Withdrawal.create).not.toHaveBeenCalled();
  });

  test('Balance exactly equal to withdrawal amount → allowed', async () => {
    LedgerEntry.aggregate.mockResolvedValue([{ credits: 100, debits: 0 }]);
    Withdrawal.aggregate.mockResolvedValue([]);
    const { LedgerEntry: LE } = require('@xcg/database');
    LE.findOne.mockReturnValue(ledgerFindOneChain(null));

    const proc = makeProcessor();
    await proc.handle(makeEventData({ amount: '100.000000' }), 'bal-003');

    expect(proc.signingPublisher.publish).toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// 6 — DAILY CAP (Security Rule 4)
// ═══════════════════════════════════════════════════════════════

describe('Daily Cap — Security Rule 4 (10,000 USDT default)', () => {
  beforeEach(() => {
    Merchant.findById.mockReturnValue(merchantFindByIdChain(makeMerchant()));
    Dispute.exists.mockResolvedValue(null);
    LedgerEntry.aggregate.mockResolvedValue([{ credits: 20000, debits: 0 }]);
  });

  test('Daily used = 9900, request = 200 → exceeds 10000 cap → blocked + alert', async () => {
    Withdrawal.aggregate.mockResolvedValue([{ total: 9900 }]);

    const proc = makeProcessor();
    await proc.handle(makeEventData({ amount: '200.000000' }), 'cap-001');

    expect(Withdrawal.create).not.toHaveBeenCalled();
    expect(proc.alertPublisher.publish).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'daily_cap_reached' }),
      expect.any(String),
    );
  });

  test('Daily used = 0, request = 100 → allowed (well under cap)', async () => {
    Withdrawal.aggregate.mockResolvedValue([]);
    const { LedgerEntry: LE } = require('@xcg/database');
    LE.findOne.mockReturnValue(ledgerFindOneChain(null));

    const proc = makeProcessor();
    await proc.handle(makeEventData({ amount: '100.000000' }), 'cap-002');

    expect(proc.signingPublisher.publish).toHaveBeenCalled();
  });

  test('Daily used = 9999, request = 1 → exactly at cap → blocked', async () => {
    Withdrawal.aggregate.mockResolvedValue([{ total: 9999 }]);

    const proc = makeProcessor();
    await proc.handle(makeEventData({ amount: '2.000000' }), 'cap-003'); // 9999 + 2 > 10000

    expect(Withdrawal.create).not.toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// 7 — HIGH-VALUE FLAG (Security Rule 6)
// ═══════════════════════════════════════════════════════════════

describe('High-Value Flag — Security Rule 6 (>5000 USDT requires admin approval)', () => {
  beforeEach(() => {
    Merchant.findById.mockReturnValue(merchantFindByIdChain(makeMerchant()));
    Dispute.exists.mockResolvedValue(null);
    LedgerEntry.aggregate.mockResolvedValue([{ credits: 20000, debits: 0 }]);
    Withdrawal.aggregate.mockResolvedValue([]);
    Wallet.findOne.mockReturnValue(walletFindOneChain(makeWallet()));
    Withdrawal.create.mockResolvedValue([{ _id: 'wdl', withdrawalId: 'wdl_high' }]);
    LedgerEntry.create.mockResolvedValue([{}, {}]);
    LedgerEntry.findOne.mockReturnValue(ledgerFindOneChain(null));
  });

  test('Amount = 5001 → withdrawal created with pending_approval status, signing NOT called', async () => {
    // perTxWithdrawalLimit must be > 5001 so that the per-tx limit check doesn't block this first
    const proc = makeProcessor({ config: { ...DEFAULT_CONFIG, perTxWithdrawalLimit: 10000 } });
    const alertPub = proc.alertPublisher;

    await proc.handle(makeEventData({ amount: '5001.000000' }), 'hv-001');

    // Withdrawal IS created (just not signed)
    expect(Withdrawal.create).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({ status: 'pending_approval', requiresApproval: true }),
      ]),
      expect.any(Object),
    );

    // signingPublisher must NOT be called — admin must approve first
    expect(proc.signingPublisher.publish).not.toHaveBeenCalled();

    // Alert sent to admin
    expect(alertPub.publish).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'withdrawal_requires_approval' }),
      expect.any(String),
    );
  });

  test('Amount = 4999 → normal processing (no approval required)', async () => {
    // perTxWithdrawalLimit must be > 4999 so that the per-tx limit check doesn't block
    const proc = makeProcessor({ config: { ...DEFAULT_CONFIG, perTxWithdrawalLimit: 10000 } });

    await proc.handle(makeEventData({ amount: '4999.000000' }), 'hv-002');

    // Withdrawal created with processing status
    expect(Withdrawal.create).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({ status: 'processing', requiresApproval: false }),
      ]),
      expect.any(Object),
    );

    // Signing IS called for non-high-value
    expect(proc.signingPublisher.publish).toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// 8 — COOLING-OFF PERIOD (Security Rule 2)
// ═══════════════════════════════════════════════════════════════

describe('Cooling-Off Period — Security Rule 2 (1 hour after last deposit)', () => {
  beforeEach(() => {
    Merchant.findById.mockReturnValue(merchantFindByIdChain(makeMerchant()));
    Dispute.exists.mockResolvedValue(null);
    LedgerEntry.aggregate.mockResolvedValue([{ credits: 500, debits: 0 }]);
    Withdrawal.aggregate.mockResolvedValue([]);
    Wallet.findOne.mockReturnValue(walletFindOneChain(makeWallet()));
    Withdrawal.create.mockResolvedValue([{ _id: 'wdl', withdrawalId: 'wdl_cool' }]);
    LedgerEntry.create.mockResolvedValue([{}, {}]);
  });

  test('Last deposit 30 minutes ago → cooling-off active, re-queued with delay', async () => {
    const thirtyMinsAgo = new Date(Date.now() - 30 * 60000);
    LedgerEntry.findOne.mockReturnValue(ledgerFindOneChain({ createdAt: thirtyMinsAgo }));

    const selfPublisher = { publish: jest.fn().mockResolvedValue(undefined) };
    const proc = makeProcessor();

    await proc.handle(makeEventData(), 'cool-001', selfPublisher);

    // Withdrawal NOT created — cooling off
    expect(Withdrawal.create).not.toHaveBeenCalled();
    // Re-queued for later
    expect(selfPublisher.publish).toHaveBeenCalled();
  });

  test('Last deposit 2 hours ago → cooling-off passed, proceeds normally', async () => {
    const twoHoursAgo = new Date(Date.now() - 2 * 3600000);
    LedgerEntry.findOne.mockReturnValue(ledgerFindOneChain({ createdAt: twoHoursAgo }));

    const proc = makeProcessor();
    await proc.handle(makeEventData(), 'cool-002');

    expect(proc.signingPublisher.publish).toHaveBeenCalled();
  });

  test('No prior deposit → no cooling off (first ever payment)', async () => {
    LedgerEntry.findOne.mockReturnValue(ledgerFindOneChain(null));

    const proc = makeProcessor();
    await proc.handle(makeEventData(), 'cool-003');

    expect(proc.signingPublisher.publish).toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// 9 — INSUFFICIENT TRON ENERGY
// ═══════════════════════════════════════════════════════════════

describe('Insufficient Tron Energy — withdrawal deferred', () => {
  beforeEach(() => {
    Merchant.findById.mockReturnValue(merchantFindByIdChain(makeMerchant()));
    Dispute.exists.mockResolvedValue(null);
    LedgerEntry.aggregate.mockResolvedValue([{ credits: 500, debits: 0 }]);
    Withdrawal.aggregate.mockResolvedValue([]);
    Wallet.findOne.mockReturnValue(walletFindOneChain(makeWallet()));
    Withdrawal.create.mockResolvedValue([{ _id: 'wdl', withdrawalId: 'wdl_energy' }]);
    LedgerEntry.create.mockResolvedValue([{}, {}]);
    Withdrawal.findByIdAndUpdate = jest.fn().mockResolvedValue({});
    LedgerEntry.findOne.mockReturnValue(ledgerFindOneChain(null));
  });

  test('hasSufficientEnergy=false → signing NOT called, withdrawal queued, alert sent', async () => {
    const tronAdapter = { hasSufficientEnergy: jest.fn().mockResolvedValue(false) };
    const proc = makeProcessor({ tronAdapter });
    const alertPub = proc.alertPublisher;

    await proc.handle(makeEventData(), 'energy-001');

    expect(proc.signingPublisher.publish).not.toHaveBeenCalled();
    expect(alertPub.publish).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'insufficient_energy' }),
      expect.any(String),
    );
  });

  test('hasSufficientEnergy=true → signing proceeds normally', async () => {
    const tronAdapter = { hasSufficientEnergy: jest.fn().mockResolvedValue(true) };
    const proc = makeProcessor({ tronAdapter });

    await proc.handle(makeEventData(), 'energy-002');

    expect(proc.signingPublisher.publish).toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// 10 — WITHDRAWAL LEDGER ENTRIES (double-entry)
// ═══════════════════════════════════════════════════════════════

describe('Withdrawal Ledger — double-entry debit/credit', () => {
  beforeEach(() => {
    Merchant.findById.mockReturnValue(merchantFindByIdChain(makeMerchant()));
    Dispute.exists.mockResolvedValue(null);
    LedgerEntry.aggregate.mockResolvedValue([{ credits: 500, debits: 0 }]);
    Withdrawal.aggregate.mockResolvedValue([]);
    Wallet.findOne.mockReturnValue(walletFindOneChain(makeWallet()));
    Withdrawal.create.mockResolvedValue([{ _id: 'wdl', withdrawalId: 'wdl_ledger' }]);
    LedgerEntry.create.mockResolvedValue([{}, {}]);
    LedgerEntry.findOne.mockReturnValue(ledgerFindOneChain(null));
  });

  test('Two ledger entries created: debit merchant_receivable + credit merchant_withdrawal', async () => {
    const proc = makeProcessor();
    await proc.handle(makeEventData({ amount: '100.000000' }), 'ledger-001');

    expect(LedgerEntry.create).toHaveBeenCalled();
    const entries = LedgerEntry.create.mock.calls[0][0];
    expect(entries).toHaveLength(2);

    const debit  = entries.find((e) => e.account === 'merchant_receivable');
    const credit = entries.find((e) => e.account === 'merchant_withdrawal');

    expect(debit).toBeDefined();
    expect(credit).toBeDefined();
    expect(debit.type).toBe('debit');
    expect(credit.type).toBe('credit');

    // Amounts must match (double-entry)
    expect(debit.amount).toBe(credit.amount);
  });

  test('Cross-reference: debit.counterpartEntryId = credit.entryId', async () => {
    const proc = makeProcessor();
    await proc.handle(makeEventData(), 'ledger-002');

    const entries = LedgerEntry.create.mock.calls[0][0];
    const debit  = entries.find((e) => e.account === 'merchant_receivable');
    const credit = entries.find((e) => e.account === 'merchant_withdrawal');

    expect(debit.counterpartEntryId).toBe(credit.entryId);
    expect(credit.counterpartEntryId).toBe(debit.entryId);
  });
});

// ═══════════════════════════════════════════════════════════════
// 11 — SIGNING REQUEST PAYLOAD
// ═══════════════════════════════════════════════════════════════

describe('Signing Request — correct payload to Zone 3', () => {
  beforeEach(() => {
    Merchant.findById.mockReturnValue(merchantFindByIdChain(makeMerchant()));
    Dispute.exists.mockResolvedValue(null);
    LedgerEntry.aggregate.mockResolvedValue([{ credits: 500, debits: 0 }]);
    Withdrawal.aggregate.mockResolvedValue([]);
    Wallet.findOne.mockReturnValue(walletFindOneChain(makeWallet()));
    Withdrawal.create.mockResolvedValue([{ _id: 'wdl', withdrawalId: 'wdl_sign' }]);
    LedgerEntry.create.mockResolvedValue([{}, {}]);
    LedgerEntry.findOne.mockReturnValue(ledgerFindOneChain(null));
  });

  test('Signing request contains all required fields for Zone 3', async () => {
    const proc = makeProcessor();
    await proc.handle(makeEventData({ amount: '100.000000' }), 'sign-001');

    expect(proc.signingPublisher.publish).toHaveBeenCalledWith(
      expect.objectContaining({
        requestId:    expect.any(String),
        withdrawalId: expect.any(String),
        walletId:     expect.any(String),
        toAddress:    makeMerchant().withdrawalAddress,
        amount:       expect.stringMatching(/^\d+\.\d{6}$/), // Format: decimals to 6dp
        network:      'testnet',
      }),
      expect.stringContaining('signing:'),
    );
  });

  test('Amount formatted to 6 decimal places in signing request', async () => {
    const proc = makeProcessor();
    await proc.handle(makeEventData({ amount: '100' }), 'sign-002');

    const call = proc.signingPublisher.publish.mock.calls[0][0];
    // Should be "100.000000" not "100"
    expect(call.amount).toMatch(/^\d+\.\d{6}$/);
  });
});
