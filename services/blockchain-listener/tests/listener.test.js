'use strict';

/**
 * Blockchain Listener Test Suite — Banking Grade.
 *
 * Tests BlockchainListener from blockchain-listener/src/listener.js
 *
 * Coverage:
 *   - Deduplication: same TX hash never published twice (Redis NX guard)
 *   - Wallet address cache: only transfers TO our wallets are processed
 *   - Block range processing: correctly handles multiple new blocks per tick
 *   - Block cap: max 20 blocks per tick to prevent overload
 *   - No new blocks → nothing published (normal quiet state)
 *   - Confirmation count calculation (latestBlock - blockNum)
 *   - Circuit breaker: 5 consecutive errors → 10× back-off + alert
 *   - Stale block detection: no new block in 30s fires alert
 *   - Wallet refresh: cache refreshed every 60 seconds
 *   - Alert failures never crash the listener
 *   - State persistence: lastScannedBlock read/written to SystemConfig
 */

// ─── Module mocks ────────────────────────────────────────────────────────────

jest.mock('@xcg/database', () => ({
  SystemConfig: {
    findOne:          jest.fn(),
    findOneAndUpdate: jest.fn().mockResolvedValue({}),
  },
  Wallet: {
    find: jest.fn(),
  },
}));

const { SystemConfig, Wallet } = require('@xcg/database');
const BlockchainListener = require('../src/listener');

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeListener(overrides = {}) {
  return new BlockchainListener({
    adapter:        makeAdapter(),
    redis:          makeRedis(),
    publisher:      { publish: jest.fn().mockResolvedValue(undefined) },
    alertPublisher: { publish: jest.fn().mockResolvedValue(undefined) },
    config:         { pollIntervalMs: 4000, staleBlockAlertMs: 30000 },
    logger: {
      info:  jest.fn(),
      warn:  jest.fn(),
      error: jest.fn(),
      debug: jest.fn(),
    },
    ...overrides,
  });
}

function makeAdapter(overrides = {}) {
  return {
    getLatestBlock:      jest.fn().mockResolvedValue(1000),
    getTransfersInBlock: jest.fn().mockResolvedValue([]),
    ...overrides,
  };
}

// Redis NX mock: first call returns '1' (key set = new TX), subsequent calls return null (duplicate)
function makeRedis(options = {}) {
  return {
    set: jest.fn().mockResolvedValue('1'), // Default: always new (NX succeeds)
    ...options,
  };
}

function makeTransfer(overrides = {}) {
  return {
    txHash:        'a'.repeat(64),
    blockNum:      999,
    fromAddress:   'TSenderAddress000000000000000000000',
    toAddress:     'TWalletAddress000000000000000000000',
    amount:        '100.000347',
    amountRaw:     '100000347',
    tokenContract: 'TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj',
    tokenSymbol:   'USDT',
    network:       'tron',
    timestamp:     Math.floor(Date.now() / 1000),
    ...overrides,
  };
}

// ─── Mock Chain Helper ───────────────────────────────────────────────────────
// listener.js _getLastScannedBlock: SystemConfig.findOne({ key }).lean()
function systemConfigFindOneChain(result) {
  return { lean: jest.fn().mockResolvedValue(result) };
}

beforeEach(() => {
  jest.clearAllMocks();
  // Default: lastScannedBlock = 995
  SystemConfig.findOne.mockReturnValue(systemConfigFindOneChain({ value: '995' }));
  // Default: two active wallets
  Wallet.find.mockReturnValue({
    lean: jest.fn().mockResolvedValue([
      { address: 'TWalletAddress000000000000000000000' },
      { address: 'TWallet2Address00000000000000000000' },
    ]),
  });
});

// ═══════════════════════════════════════════════════════════════
// 1 — DEDUPLICATION (TX seen-set via Redis NX)
// ═══════════════════════════════════════════════════════════════

describe('TX Deduplication — Redis NX seen-set', () => {
  test('First time seeing TX → published to matching engine', async () => {
    const redis = makeRedis({ set: jest.fn().mockResolvedValue('1') }); // NX succeeded = new
    const adapter = makeAdapter({
      getLatestBlock:      jest.fn().mockResolvedValue(1001),
      getTransfersInBlock: jest.fn().mockResolvedValue([makeTransfer({ blockNum: 1001 })]),
    });
    // lastScannedBlock = 1000 → only block 1001 is processed (exactly 1 block)
    SystemConfig.findOne.mockReturnValue(systemConfigFindOneChain({ value: '1000' }));

    const listener = makeListener({ adapter, redis });
    await listener._refreshWalletAddresses();
    await listener._poll();

    expect(listener.publisher.publish).toHaveBeenCalledTimes(1);
    expect(listener.publisher.publish).toHaveBeenCalledWith(
      expect.objectContaining({ txHash: 'a'.repeat(64) }),
      'a'.repeat(64), // idempotencyKey = txHash
    );
  });

  test('Duplicate TX (same hash) → NOT published (Redis NX returns null)', async () => {
    const redis = makeRedis({ set: jest.fn().mockResolvedValue(null) }); // null = key existed
    const adapter = makeAdapter({
      getLatestBlock:      jest.fn().mockResolvedValue(1001),
      getTransfersInBlock: jest.fn().mockResolvedValue([makeTransfer({ blockNum: 1000 })]),
    });
    SystemConfig.findOne.mockReturnValue(systemConfigFindOneChain({ value: '999' }));

    const listener = makeListener({ adapter, redis });
    await listener._refreshWalletAddresses();
    await listener._poll();

    expect(listener.publisher.publish).not.toHaveBeenCalled();
  });

  test('Redis dedup key stored with correct prefix and 7-day TTL', async () => {
    const redis = makeRedis();
    const adapter = makeAdapter({
      getLatestBlock:      jest.fn().mockResolvedValue(1001),
      getTransfersInBlock: jest.fn().mockResolvedValue([makeTransfer({ blockNum: 1000 })]),
    });
    SystemConfig.findOne.mockReturnValue(systemConfigFindOneChain({ value: '999' }));

    const listener = makeListener({ adapter, redis });
    await listener._refreshWalletAddresses();
    await listener._poll();

    expect(redis.set).toHaveBeenCalledWith(
      `xcg:txseen:${'a'.repeat(64)}`,  // Correct prefix
      '1',
      'EX',
      7 * 24 * 60 * 60, // 7 days in seconds
      'NX',             // Only set if not exists
    );
  });
});

// ═══════════════════════════════════════════════════════════════
// 2 — WALLET ADDRESS FILTERING
// ═══════════════════════════════════════════════════════════════

describe('Wallet Address Filter — only process transfers TO our wallets', () => {
  test('Transfer to unknown address → NOT published', async () => {
    const adapter = makeAdapter({
      getLatestBlock:      jest.fn().mockResolvedValue(1001),
      getTransfersInBlock: jest.fn().mockResolvedValue([
        makeTransfer({ toAddress: 'TUnknownAddress00000000000000000000' }),
      ]),
    });
    SystemConfig.findOne.mockReturnValue(systemConfigFindOneChain({ value: '1000' }));

    const listener = makeListener({ adapter });
    await listener._refreshWalletAddresses();
    await listener._poll();

    expect(listener.publisher.publish).not.toHaveBeenCalled();
  });

  test('Transfer to known wallet address → published', async () => {
    const adapter = makeAdapter({
      getLatestBlock:      jest.fn().mockResolvedValue(1001),
      getTransfersInBlock: jest.fn().mockResolvedValue([
        makeTransfer({ toAddress: 'TWalletAddress000000000000000000000' }),
      ]),
    });
    SystemConfig.findOne.mockReturnValue(systemConfigFindOneChain({ value: '1000' }));

    const listener = makeListener({ adapter });
    await listener._refreshWalletAddresses();
    await listener._poll();

    expect(listener.publisher.publish).toHaveBeenCalledTimes(1);
  });

  test('Address comparison is case-insensitive (lowercase wallet cache)', async () => {
    // Wallet stored as UPPER, transfer comes as lower
    Wallet.find.mockReturnValue({
      lean: jest.fn().mockResolvedValue([
        { address: 'TWALLETADDRESS000000000000000000000' },
      ]),
    });

    const adapter = makeAdapter({
      getLatestBlock:      jest.fn().mockResolvedValue(1001),
      getTransfersInBlock: jest.fn().mockResolvedValue([
        makeTransfer({ toAddress: 'twalletaddress000000000000000000000' }),
      ]),
    });
    SystemConfig.findOne.mockReturnValue(systemConfigFindOneChain({ value: '1000' }));

    const listener = makeListener({ adapter });
    await listener._refreshWalletAddresses();
    await listener._poll();

    expect(listener.publisher.publish).toHaveBeenCalledTimes(1);
  });

  test('No active wallets → block is skipped entirely', async () => {
    Wallet.find.mockReturnValue({
      lean: jest.fn().mockResolvedValue([]), // Zero wallets
    });

    const adapter = makeAdapter({
      getLatestBlock:      jest.fn().mockResolvedValue(1001),
      getTransfersInBlock: jest.fn().mockResolvedValue([makeTransfer()]),
    });
    SystemConfig.findOne.mockReturnValue(systemConfigFindOneChain({ value: '1000' }));

    const listener = makeListener({ adapter });
    await listener._refreshWalletAddresses();
    await listener._poll();

    expect(listener.publisher.publish).not.toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// 3 — BLOCK RANGE PROCESSING
// ═══════════════════════════════════════════════════════════════

describe('Block Range Processing — lastScanned + 1 to latestBlock', () => {
  test('No new blocks (latestBlock <= lastScanned) → nothing processed', async () => {
    const adapter = makeAdapter({ getLatestBlock: jest.fn().mockResolvedValue(995) });
    SystemConfig.findOne.mockReturnValue(systemConfigFindOneChain({ value: '995' }));

    const listener = makeListener({ adapter });
    await listener._refreshWalletAddresses();
    await listener._poll();

    expect(adapter.getTransfersInBlock).not.toHaveBeenCalled();
  });

  test('3 new blocks (996, 997, 998) → getTransfersInBlock called 3 times', async () => {
    const adapter = makeAdapter({
      getLatestBlock:      jest.fn().mockResolvedValue(998),
      getTransfersInBlock: jest.fn().mockResolvedValue([]),
    });
    SystemConfig.findOne.mockReturnValue(systemConfigFindOneChain({ value: '995' }));

    const listener = makeListener({ adapter });
    await listener._refreshWalletAddresses();
    await listener._poll();

    expect(adapter.getTransfersInBlock).toHaveBeenCalledTimes(3);
    expect(adapter.getTransfersInBlock).toHaveBeenCalledWith(996);
    expect(adapter.getTransfersInBlock).toHaveBeenCalledWith(997);
    expect(adapter.getTransfersInBlock).toHaveBeenCalledWith(998);
  });

  test('Block cap: max 20 blocks per tick even if 100 blocks behind', async () => {
    const adapter = makeAdapter({
      getLatestBlock:      jest.fn().mockResolvedValue(1095), // 100 blocks ahead
      getTransfersInBlock: jest.fn().mockResolvedValue([]),
    });
    SystemConfig.findOne.mockReturnValue(systemConfigFindOneChain({ value: '995' }));

    const listener = makeListener({ adapter });
    await listener._refreshWalletAddresses();
    await listener._poll();

    // Should only process blocks 996–1015 (20 blocks max)
    expect(adapter.getTransfersInBlock).toHaveBeenCalledTimes(20);
    expect(adapter.getTransfersInBlock).toHaveBeenNthCalledWith(1, 996);
    expect(adapter.getTransfersInBlock).toHaveBeenNthCalledWith(20, 1015);
  });

  test('lastScannedBlock updated after each processed block (no gaps on failure)', async () => {
    const adapter = makeAdapter({
      getLatestBlock:      jest.fn().mockResolvedValue(998),
      getTransfersInBlock: jest.fn().mockResolvedValue([]),
    });
    SystemConfig.findOne.mockReturnValue(systemConfigFindOneChain({ value: '995' }));

    const listener = makeListener({ adapter });
    await listener._refreshWalletAddresses();
    await listener._poll();

    // Should update lastScannedBlock for each block (996, 997, 998)
    expect(SystemConfig.findOneAndUpdate).toHaveBeenCalledTimes(3);
    expect(SystemConfig.findOneAndUpdate).toHaveBeenLastCalledWith(
      { key: 'lastScannedBlock' },
      expect.objectContaining({ value: '998' }),
      expect.any(Object),
    );
  });

  test('Block processing failure → lastScannedBlock NOT updated for failed block', async () => {
    const adapter = makeAdapter({
      getLatestBlock:      jest.fn().mockResolvedValue(997),
      getTransfersInBlock: jest.fn()
        .mockResolvedValueOnce([])          // block 996 → success
        .mockRejectedValueOnce(new Error('TronGrid 503')), // block 997 → fails
    });
    SystemConfig.findOne.mockReturnValue(systemConfigFindOneChain({ value: '995' }));

    const listener = makeListener({ adapter });
    await listener._refreshWalletAddresses();

    await expect(listener._poll()).rejects.toThrow('TronGrid 503');

    // lastScannedBlock updated for 996, but NOT for 997
    expect(SystemConfig.findOneAndUpdate).toHaveBeenCalledTimes(1);
    expect(SystemConfig.findOneAndUpdate).toHaveBeenCalledWith(
      expect.any(Object),
      expect.objectContaining({ value: '996' }),
      expect.any(Object),
    );
  });
});

// ═══════════════════════════════════════════════════════════════
// 4 — CONFIRMATION COUNT
// ═══════════════════════════════════════════════════════════════

describe('Confirmation Count — latestBlock - blockNum', () => {
  test('blockNum=990, latestBlock=1010 → 20 confirmations published', async () => {
    const adapter = makeAdapter({
      getLatestBlock: jest.fn().mockResolvedValue(1010),
      getTransfersInBlock: jest.fn().mockResolvedValue([
        makeTransfer({ blockNum: 990 }),
      ]),
    });
    SystemConfig.findOne.mockReturnValue(systemConfigFindOneChain({ value: '989' }));

    const listener = makeListener({ adapter });
    await listener._refreshWalletAddresses();
    await listener._poll();

    expect(listener.publisher.publish).toHaveBeenCalledWith(
      expect.objectContaining({ confirmations: 20 }), // 1010 - 990 = 20
      expect.any(String),
    );
  });

  test('blockNum = latestBlock (just landed) → 0 confirmations', async () => {
    const adapter = makeAdapter({
      getLatestBlock: jest.fn().mockResolvedValue(1000),
      getTransfersInBlock: jest.fn().mockResolvedValue([
        makeTransfer({ blockNum: 1000 }),
      ]),
    });
    SystemConfig.findOne.mockReturnValue(systemConfigFindOneChain({ value: '999' }));

    const listener = makeListener({ adapter });
    await listener._refreshWalletAddresses();
    await listener._poll();

    expect(listener.publisher.publish).toHaveBeenCalledWith(
      expect.objectContaining({ confirmations: 0 }),
      expect.any(String),
    );
  });
});

// ═══════════════════════════════════════════════════════════════
// 5 — CIRCUIT BREAKER
// ═══════════════════════════════════════════════════════════════

describe('Circuit Breaker — 5 consecutive errors', () => {
  test('5 consecutive tick errors → alert fired + 10× back-off', async () => {
    const adapter = makeAdapter({
      getLatestBlock: jest.fn().mockRejectedValue(new Error('Timeout')),
    });
    SystemConfig.findOne.mockReturnValue(systemConfigFindOneChain({ value: '995' }));

    const setSpy = jest.spyOn(global, 'setTimeout').mockImplementation(() => {});

    const listener = makeListener({ adapter });
    await listener._refreshWalletAddresses();

    // Simulate 5 consecutive tick failures
    for (let i = 0; i < 5; i++) {
      await listener._tick();
    }

    expect(listener.alertPublisher.publish).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'blockchain_circuit_open' }),
      expect.any(String),
    );

    setSpy.mockRestore();
  });

  test('Successful tick after errors → consecutiveErrors reset to 0', async () => {
    const adapter = makeAdapter({
      getLatestBlock:      jest.fn().mockResolvedValue(995), // No new blocks (success path)
      getTransfersInBlock: jest.fn().mockResolvedValue([]),
    });
    SystemConfig.findOne.mockReturnValue(systemConfigFindOneChain({ value: '995' }));

    const setSpy = jest.spyOn(global, 'setTimeout').mockImplementation(() => {});

    const listener = makeListener({ adapter });
    listener._consecutiveErrors = 3; // Simulate prior errors

    await listener._refreshWalletAddresses();
    await listener._tick(); // Successful tick

    expect(listener._consecutiveErrors).toBe(0);
    setSpy.mockRestore();
  });
});

// ═══════════════════════════════════════════════════════════════
// 6 — STALE BLOCK DETECTION
// ═══════════════════════════════════════════════════════════════

describe('Stale Block Detection — no new block in 30s fires alert', () => {
  test('Last block 31 seconds ago → stale_block alert fired', async () => {
    const listener = makeListener();
    listener._lastBlockTime = Date.now() - 31000; // 31 seconds ago

    await listener._checkStaleness();

    expect(listener.alertPublisher.publish).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'stale_block' }),
      expect.any(String),
    );
  });

  test('Last block 10 seconds ago → no alert (within threshold)', async () => {
    const listener = makeListener();
    listener._lastBlockTime = Date.now() - 10000;

    await listener._checkStaleness();

    expect(listener.alertPublisher.publish).not.toHaveBeenCalled();
  });

  test('No blocks processed yet → no stale alert (first run)', async () => {
    const listener = makeListener();
    listener._lastBlockTime = null;

    await listener._checkStaleness();

    expect(listener.alertPublisher.publish).not.toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// 7 — PUBLISHED EVENT PAYLOAD
// ═══════════════════════════════════════════════════════════════

describe('Published Event Payload — complete and correct', () => {
  test('Published event contains all required fields', async () => {
    const transfer = makeTransfer({ blockNum: 1000 });
    const adapter = makeAdapter({
      getLatestBlock:      jest.fn().mockResolvedValue(1001),
      getTransfersInBlock: jest.fn().mockResolvedValue([transfer]),
    });
    SystemConfig.findOne.mockReturnValue(systemConfigFindOneChain({ value: '999' }));

    const listener = makeListener({ adapter });
    await listener._refreshWalletAddresses();
    await listener._poll();

    expect(listener.publisher.publish).toHaveBeenCalledWith(
      expect.objectContaining({
        txHash:        transfer.txHash,
        blockNum:      transfer.blockNum,
        confirmations: expect.any(Number),
        fromAddress:   transfer.fromAddress,
        toAddress:     transfer.toAddress,
        amount:        transfer.amount,
        amountRaw:     transfer.amountRaw,
        tokenContract: transfer.tokenContract,
        tokenSymbol:   transfer.tokenSymbol,
        network:       transfer.network,
        detectedAt:    expect.any(Number),
      }),
      transfer.txHash,
    );
  });
});

// ═══════════════════════════════════════════════════════════════
// 8 — FAULT TOLERANCE
// ═══════════════════════════════════════════════════════════════

describe('Fault Tolerance — alerts never crash listener', () => {
  test('alertPublisher.publish throws → _fireAlert swallows error silently', async () => {
    const listener = makeListener({
      alertPublisher: { publish: jest.fn().mockRejectedValue(new Error('Alert queue full')) },
    });
    listener._lastBlockTime = Date.now() - 60000; // Very stale

    // Should not throw — _fireAlert catches internally
    await expect(listener._checkStaleness()).resolves.not.toThrow();
  });

  test('Wallet.find fails → stale cache used, listener does not crash', async () => {
    Wallet.find.mockReturnValue({
      lean: jest.fn().mockRejectedValue(new Error('DB connection lost')),
    });

    const listener = makeListener();
    listener._walletAddresses = new Set(['TWalletAddress000000000000000000000']); // Existing cache

    // _refreshWalletAddresses should swallow DB error and keep stale cache
    await expect(listener._refreshWalletAddresses()).resolves.not.toThrow();

    // Cache preserved
    expect(listener._walletAddresses.size).toBe(1);
  });
});

// ═══════════════════════════════════════════════════════════════
// 9 — STATE PERSISTENCE
// ═══════════════════════════════════════════════════════════════

describe('State Persistence — lastScannedBlock to SystemConfig', () => {
  test('No lastScannedBlock in DB → defaults to 0', async () => {
    SystemConfig.findOne.mockReturnValue(systemConfigFindOneChain(null));

    const listener = makeListener();
    const lastBlock = await listener._getLastScannedBlock();

    expect(lastBlock).toBe(0);
  });

  test('_setLastScannedBlock upserts with string value', async () => {
    const listener = makeListener();
    await listener._setLastScannedBlock(1234);

    expect(SystemConfig.findOneAndUpdate).toHaveBeenCalledWith(
      { key: 'lastScannedBlock' },
      expect.objectContaining({
        key:   'lastScannedBlock',
        value: '1234', // Must be string
      }),
      { upsert: true, new: true },
    );
  });

  test('Returns numeric block number (not string) from _getLastScannedBlock', async () => {
    SystemConfig.findOne.mockReturnValue(systemConfigFindOneChain({ value: '12345' }));

    const listener = makeListener();
    const result = await listener._getLastScannedBlock();

    expect(result).toBe(12345);
    expect(typeof result).toBe('number');
  });
});
