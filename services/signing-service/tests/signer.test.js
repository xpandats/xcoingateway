'use strict';

/**
 * Signing Service Test Suite — Banking Grade (Zone 3 Security).
 *
 * Tests the most security-critical service in the system: signer.js
 *
 * SECURITY FOCUS:
 *   - Private key Buffer is ZEROED after every signing operation (including errors)
 *   - Private key is NEVER returned from sign(), NEVER in logs
 *   - Invalid Joi schema → rejected before key access (no decryption attempted)
 *   - Inactive/missing wallet → rejected before key access
 *   - Unknown network → constructor throws (fails fast)
 *   - Audit log written for every outcome (success + failure)
 *   - Audit log failure never blocks signing
 */

// ─── Module mocks ────────────────────────────────────────────────────────────

jest.mock('@xcg/database', () => ({
  Wallet:   { findById: jest.fn() },
  AuditLog: { create:  jest.fn() },
}));

jest.mock('@xcg/crypto', () => ({
  decrypt: jest.fn(),
}));

// TronWeb mock — full transaction lifecycle
const mockTriggerSmartContract = jest.fn();
const mockSign                 = jest.fn();
const mockSendRawTransaction   = jest.fn();

jest.mock('@xcg/tron', () => ({
  getTronWeb: jest.fn().mockReturnValue({
    transactionBuilder: { triggerSmartContract: mockTriggerSmartContract },
    trx: {
      sign:               mockSign,
      sendRawTransaction: mockSendRawTransaction,
    },
    defaultPrivateKey: null,
  }),
}));

const { Wallet, AuditLog } = require('@xcg/database');
const { decrypt }          = require('@xcg/crypto');
const Signer               = require('../src/signer');

// ─── Helpers ─────────────────────────────────────────────────────────────────

const MASTER_KEY = 'a'.repeat(64);

function makeSigner() {
  return new Signer({
    network:   'testnet',
    apiKey:    'test-api-key',
    masterKey: MASTER_KEY,
    logger: {
      info:  jest.fn(),
      warn:  jest.fn(),
      error: jest.fn(),
      debug: jest.fn(),
    },
  });
}

function makeRequest(overrides = {}) {
  return {
    requestId:    'a0000000-0000-4000-b000-000000000001',
    withdrawalId: 'a'.repeat(24),
    walletId:     'b'.repeat(24),
    toAddress:    'TN3W4T7pk41MMxL1mjC6HeMoAWH7aA4X9F',
    amount:       '150.000000',
    network:      'testnet',
    ...overrides,
  };
}

function makeWallet(overrides = {}) {
  return {
    _id:                'b'.repeat(24),
    address:            'THotWallet0000000000000000000000001',
    isActive:           true,
    encryptedPrivateKey: 'encrypted_key_blob',
    ...overrides,
  };
}

// A fake decrypted private key buffer — will be checked for zeroing
function makeFakeKeyBuffer() {
  const buf = Buffer.alloc(32, 0xAB); // 32 bytes of 0xAB
  return buf;
}

// ─── Mock Chain Helper ───────────────────────────────────────────────────────
// signer.js: Wallet.findById(id).select('+encryptedPrivateKey').lean()
// The result must support .select().lean() chaining.
function walletFindByIdChain(result) {
  return {
    select: jest.fn().mockReturnValue({
      lean: jest.fn().mockResolvedValue(result),
    }),
  };
}

beforeEach(() => {
  jest.clearAllMocks();
  AuditLog.create.mockResolvedValue({});
  // Default: no wallet found (safe fallback — tests override as needed)
  Wallet.findById.mockReturnValue(walletFindByIdChain(null));
});

// ═══════════════════════════════════════════════════════════════
// 1 — CONSTRUCTOR VALIDATION
// ═══════════════════════════════════════════════════════════════

describe('Constructor — network validation', () => {
  test('unknown network → throws immediately (fail fast)', () => {
    expect(() => new Signer({
      network:   'ethereum',
      apiKey:    'key',
      masterKey: MASTER_KEY,
      logger:    { info: jest.fn(), error: jest.fn() },
    })).toThrow('unknown network');
  });

  test('mainnet network → accepted', () => {
    expect(() => new Signer({
      network:   'mainnet',
      apiKey:    'key',
      masterKey: MASTER_KEY,
      logger:    { info: jest.fn(), error: jest.fn() },
    })).not.toThrow();
  });

  test('testnet network → accepted', () => {
    expect(() => makeSigner()).not.toThrow();
  });
});

// ═══════════════════════════════════════════════════════════════
// 2 — INPUT VALIDATION (Joi schema — before key access)
// ═══════════════════════════════════════════════════════════════

describe('Request Schema Validation — key never accessed on invalid input', () => {
  beforeEach(() => {
    Wallet.findById.mockReturnValue(walletFindByIdChain(makeWallet()));
    decrypt.mockReturnValue(makeFakeKeyBuffer());
  });

  test('Missing requestId → throws, Wallet.findById never called', async () => {
    const signer = makeSigner();
    await expect(signer.sign(makeRequest({ requestId: undefined }))).rejects.toThrow();
    expect(Wallet.findById).not.toHaveBeenCalled();
  });

  test('Invalid UUID requestId → throws before DB access', async () => {
    const signer = makeSigner();
    await expect(signer.sign(makeRequest({ requestId: 'not-a-uuid' }))).rejects.toThrow('Signer: invalid request');
    expect(Wallet.findById).not.toHaveBeenCalled();
  });

  test('Non-Tron toAddress (ETH address) → rejected before key access', async () => {
    const signer = makeSigner();
    await expect(
      signer.sign(makeRequest({ toAddress: '0x742d35Cc6634C0532925a3b8D4C9C2C4a74fb' })),
    ).rejects.toThrow('Signer: invalid request');
    expect(Wallet.findById).not.toHaveBeenCalled();
  });

  test('Invalid amount format ("100" with no decimal) → rejected', async () => {
    const signer = makeSigner();
    // Schema requires pattern /^\d+\.\d{1,6}$/ — "100" has no decimal
    await expect(
      signer.sign(makeRequest({ amount: '100' })),
    ).rejects.toThrow('Signer: invalid request');
    expect(Wallet.findById).not.toHaveBeenCalled();
  });

  test('Invalid walletId (not 24 hex chars) → rejected', async () => {
    const signer = makeSigner();
    await expect(
      signer.sign(makeRequest({ walletId: 'not-valid' })),
    ).rejects.toThrow('Signer: invalid request');
    expect(Wallet.findById).not.toHaveBeenCalled();
  });

  test('Unknown network type → rejected by Joi', async () => {
    const signer = makeSigner();
    await expect(
      signer.sign(makeRequest({ network: 'ethereum' })),
    ).rejects.toThrow('Signer: invalid request');
    expect(Wallet.findById).not.toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// 3 — WALLET VALIDATION (after schema, before key decryption)
// ═══════════════════════════════════════════════════════════════

describe('Wallet Validation — key not decrypted for invalid wallets', () => {
  test('Wallet not found → throws before decrypt', async () => {
    Wallet.findById.mockReturnValue(walletFindByIdChain(null));

    const signer = makeSigner();
    await expect(signer.sign(makeRequest())).rejects.toThrow('not found or inactive');
    expect(decrypt).not.toHaveBeenCalled();
  });

  test('Wallet is inactive → throws before decrypt', async () => {
    Wallet.findById.mockReturnValue(walletFindByIdChain(makeWallet({ isActive: false })));

    const signer = makeSigner();
    await expect(signer.sign(makeRequest())).rejects.toThrow('not found or inactive');
    expect(decrypt).not.toHaveBeenCalled();
  });

  test('Wallet has no encryptedPrivateKey → throws before decrypt', async () => {
    Wallet.findById.mockReturnValue(walletFindByIdChain(makeWallet({ encryptedPrivateKey: null })));

    const signer = makeSigner();
    await expect(signer.sign(makeRequest())).rejects.toThrow('no encrypted key');
    expect(decrypt).not.toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// 4 — PRIVATE KEY ZEROING (core security property)
// ═══════════════════════════════════════════════════════════════

describe('Private Key Zeroing — critical security contract', () => {
  test('Successful signing: key buffer is zeroed immediately after signing', async () => {
    const fakeKey = makeFakeKeyBuffer();
    const fillSpy = jest.spyOn(fakeKey, 'fill');

    Wallet.findById.mockReturnValue(walletFindByIdChain(makeWallet()));
    decrypt.mockReturnValue(fakeKey);

    mockTriggerSmartContract.mockResolvedValue({
      result: { result: true },
      transaction: { txID: 'tx123', rawData: {} },
    });
    mockSign.mockResolvedValue({ txID: 'tx123' });
    mockSendRawTransaction.mockResolvedValue({ result: true, txid: 'b'.repeat(64) });

    const signer = makeSigner();
    await signer.sign(makeRequest());

    // Buffer.fill(0) MUST have been called on the private key buffer
    expect(fillSpy).toHaveBeenCalledWith(0);
  });

  test('Signing fails (TronWeb error): key buffer is STILL zeroed in catch block', async () => {
    const fakeKey = makeFakeKeyBuffer();
    const fillSpy = jest.spyOn(fakeKey, 'fill');

    Wallet.findById.mockReturnValue(walletFindByIdChain(makeWallet()));
    decrypt.mockReturnValue(fakeKey);

    mockTriggerSmartContract.mockRejectedValue(new Error('TronGrid connection refused'));

    const signer = makeSigner();
    await expect(signer.sign(makeRequest())).rejects.toThrow();

    // Key MUST be zeroed even on error
    expect(fillSpy).toHaveBeenCalledWith(0);
  });

  test('decrypt() returns non-Buffer → throws (Buffer required for zeroing)', async () => {
    Wallet.findById.mockReturnValue(walletFindByIdChain(makeWallet()));
    // Return a string instead of Buffer (simulating wrong decrypt implementation)
    decrypt.mockReturnValue('private_key_as_string_NOT_safe');

    const signer = makeSigner();
    await expect(signer.sign(makeRequest())).rejects.toThrow('must return a Buffer');
  });
});

// ═══════════════════════════════════════════════════════════════
// 5 — HAPPY PATH: correct TronWeb call sequence
// ═══════════════════════════════════════════════════════════════

describe('Happy Path — correct TronWeb call sequence', () => {
  const TX_HASH = 'd'.repeat(64);

  beforeEach(() => {
    Wallet.findById.mockReturnValue(walletFindByIdChain(makeWallet()));
    decrypt.mockReturnValue(makeFakeKeyBuffer());

    mockTriggerSmartContract.mockResolvedValue({
      result: { result: true },
      transaction: { txID: TX_HASH, rawData: {} },
    });
    mockSign.mockResolvedValue({ txID: TX_HASH });
    mockSendRawTransaction.mockResolvedValue({ result: true, txid: TX_HASH });
  });

  test('sign() returns txHash on success', async () => {
    const signer = makeSigner();
    const result = await signer.sign(makeRequest());

    expect(result).toEqual({ txHash: TX_HASH });
  });

  test('triggerSmartContract called with correct USDT testnet contract', async () => {
    const signer = makeSigner();
    await signer.sign(makeRequest());

    expect(mockTriggerSmartContract).toHaveBeenCalledWith(
      'TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj', // Testnet USDT
      'transfer(address,uint256)',
      expect.any(Object),
      expect.any(Array),
      makeWallet().address,
    );
  });

  test('triggerSmartContract amount converted to SUN (× 1,000,000)', async () => {
    const signer = makeSigner();
    await signer.sign(makeRequest({ amount: '150.000000' }));

    const callArgs = mockTriggerSmartContract.mock.calls[0];
    const params = callArgs[3]; // Array of { type, value }
    const amountParam = params.find((p) => p.type === 'uint256');

    // 150.000000 USDT × 1,000,000 = 150,000,000 SUN
    expect(amountParam.value).toBe('150000000');
  });

  test('trx.sign called before sendRawTransaction (correct sequence)', async () => {
    const callOrder = [];
    mockSign.mockImplementation(async () => { callOrder.push('sign'); return { txID: TX_HASH }; });
    mockSendRawTransaction.mockImplementation(async () => { callOrder.push('send'); return { result: true, txid: TX_HASH }; });

    const signer = makeSigner();
    await signer.sign(makeRequest());

    expect(callOrder).toEqual(['sign', 'send']);
  });
});

// ═══════════════════════════════════════════════════════════════
// 6 — AUDIT LOG
// ═══════════════════════════════════════════════════════════════

describe('Audit Log — every operation recorded', () => {
  const TX_HASH = 'e'.repeat(64);

  beforeEach(() => {
    Wallet.findById.mockReturnValue(walletFindByIdChain(makeWallet()));
    decrypt.mockReturnValue(makeFakeKeyBuffer());
    mockTriggerSmartContract.mockResolvedValue({ result: { result: true }, transaction: { txID: TX_HASH } });
    mockSign.mockResolvedValue({ txID: TX_HASH });
    mockSendRawTransaction.mockResolvedValue({ result: true, txid: TX_HASH });
  });

  test('Successful signing writes audit log with outcome=success', async () => {
    const signer = makeSigner();
    await signer.sign(makeRequest());

    expect(AuditLog.create).toHaveBeenCalledWith(
      expect.objectContaining({
        actor:   'signing-service',
        action:  'signing_operation',
        outcome: 'success',
        metadata: expect.objectContaining({
          txHash: TX_HASH,
        }),
      }),
    );
  });

  test('Failed signing writes audit log with outcome=failed', async () => {
    mockTriggerSmartContract.mockRejectedValue(new Error('Network error'));
    decrypt.mockReturnValue(makeFakeKeyBuffer());

    const signer = makeSigner();
    await expect(signer.sign(makeRequest())).rejects.toThrow();

    expect(AuditLog.create).toHaveBeenCalledWith(
      expect.objectContaining({
        actor:   'signing-service',
        outcome: 'failed',
        metadata: expect.objectContaining({ error: 'Network error' }),
      }),
    );
  });

  test('Audit log does NOT contain private key in any field', async () => {
    const FAKE_KEY_HEX = 'ab'.repeat(32); // What the private key would look like as hex

    // Use a real buffer so fill() works
    const keyBuf = Buffer.from(FAKE_KEY_HEX, 'hex');
    decrypt.mockReturnValue(keyBuf);

    const signer = makeSigner();
    await signer.sign(makeRequest());

    const auditCall = AuditLog.create.mock.calls[0][0];
    const auditStr  = JSON.stringify(auditCall);

    // Private key hex string must NOT appear anywhere in the audit log
    expect(auditStr).not.toContain(FAKE_KEY_HEX);
  });

  test('AuditLog.create throws → signing still returns result (never blocks)', async () => {
    AuditLog.create.mockRejectedValue(new Error('Audit DB down'));

    const signer = makeSigner();
    const result = await signer.sign(makeRequest());

    expect(result).toHaveProperty('txHash');
  });
});

// ═══════════════════════════════════════════════════════════════
// 7 — BROADCAST FAILURE
// ═══════════════════════════════════════════════════════════════

describe('Broadcast Failure — rejection after signing', () => {
  test('sendRawTransaction returns result:false → throws after zeroing key', async () => {
    const fakeKey = makeFakeKeyBuffer();
    const fillSpy = jest.spyOn(fakeKey, 'fill');

    Wallet.findById.mockReturnValue(walletFindByIdChain(makeWallet()));
    decrypt.mockReturnValue(fakeKey);
    mockTriggerSmartContract.mockResolvedValue({ result: { result: true }, transaction: { txID: 'tx' } });
    mockSign.mockResolvedValue({ txID: 'tx' });
    mockSendRawTransaction.mockResolvedValue({ result: false, code: 'SIGERROR' });

    const signer = makeSigner();
    await expect(signer.sign(makeRequest())).rejects.toThrow('broadcast failed');

    // Key must be zeroed even when broadcast fails
    expect(fillSpy).toHaveBeenCalledWith(0);
  });

  test('No txHash returned from broadcast → throws', async () => {
    Wallet.findById.mockReturnValue(walletFindByIdChain(makeWallet()));
    decrypt.mockReturnValue(makeFakeKeyBuffer());
    mockTriggerSmartContract.mockResolvedValue({ result: { result: true }, transaction: {} });
    mockSign.mockResolvedValue({ txID: null });
    mockSendRawTransaction.mockResolvedValue({ result: true, txid: null });

    const signer = makeSigner();
    await expect(signer.sign(makeRequest())).rejects.toThrow('no txHash');
  });
});
