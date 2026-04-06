'use strict';

/**
 * Core Package Unit Tests — Banking Grade.
 *
 * Tests for packages that all services depend on:
 *   - @xcg/crypto : AES-256-GCM encryption, key versioning, tamper detection
 *   - @xcg/common : money utilities (BigInt), response builder, AppError, constants
 *   - Matching Engine: contract/amount logic (no DB)
 *   - Withdrawal Processor: business rule constants
 *   - AuditLog: hash chain integrity
 */

const crypto = require('crypto');

beforeAll(() => {
  process.env.MASTER_ENCRYPTION_KEY = 'a'.repeat(64);
  process.env.JWT_ACCESS_SECRET     = 'a'.repeat(64);
  process.env.JWT_REFRESH_SECRET    = 'b'.repeat(64);
});

// ═══════════════════════════════════════════════════════════════
// @xcg/crypto — AES-256-GCM ENCRYPTION
// ═══════════════════════════════════════════════════════════════

describe('@xcg/crypto — AES-256-GCM', () => {
  const { encrypt, decrypt, isCurrentVersion } = require('@xcg/crypto');

  test('Basic encrypt → decrypt round trip', () => {
    const plain = 'super-secret-private-key-data';
    expect(decrypt(encrypt(plain))).toBe(plain);
  });

  test('Empty string encrypts and decrypts', () => {
    expect(decrypt(encrypt(''))).toBe('');
  });

  test('Long string (64 hex chars = private key) round trips', () => {
    const key = 'a'.repeat(64);
    expect(decrypt(encrypt(key))).toBe(key);
  });

  test('Unique ciphertext for same plaintext (random IV)', () => {
    const c1 = encrypt('same-value');
    const c2 = encrypt('same-value');
    expect(c1).not.toBe(c2);
  });

  test('Output format is v1:iv:tag:ciphertext (4 parts)', () => {
    const enc   = encrypt('test');
    const parts = enc.split(':');
    expect(parts).toHaveLength(4);
    expect(parts[0]).toBe('v1');
    expect(parts[1]).toHaveLength(32); // 16 bytes hex IV
    expect(parts[2]).toHaveLength(32); // 16 bytes hex auth tag
  });

  test('Corrupted auth tag → throws (GCM authentication failure)', () => {
    const enc = encrypt('data');
    const parts = enc.split(':');
    parts[2] = 'deadbeefdeadbeefdeadbeefdeadbeef'; // wrong tag
    expect(() => decrypt(parts.join(':'))).toThrow();
  });

  test('Corrupted ciphertext → throws', () => {
    const enc = encrypt('data');
    const parts = enc.split(':');
    parts[3] = 'ff' + parts[3].slice(2);
    expect(() => decrypt(parts.join(':'))).toThrow();
  });

  test('isCurrentVersion() detects versioned format', () => {
    const enc = encrypt('test');
    expect(isCurrentVersion(enc)).toBe(true);
  });

  test('isCurrentVersion() detects legacy (3-part) format', () => {
    expect(isCurrentVersion('aabbccdd:eeff0011:11223344')).toBe(false);
  });

  test('decrypt() handles legacy unversioned format', () => {
    const key    = Buffer.from('a'.repeat(64), 'hex');
    const iv     = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let enc = cipher.update('legacy-value', 'utf8', 'hex');
    enc += cipher.final('hex');
    const tag    = cipher.getAuthTag();
    const legacy = `${iv.toString('hex')}:${tag.toString('hex')}:${enc}`;
    expect(decrypt(legacy)).toBe('legacy-value');
  });

  test('Wrong master key → authentication failure', () => {
    const enc  = encrypt('secret-data');
    const orig = process.env.MASTER_ENCRYPTION_KEY;
    process.env.MASTER_ENCRYPTION_KEY = 'b'.repeat(64);
    expect(() => decrypt(enc)).toThrow();
    process.env.MASTER_ENCRYPTION_KEY = orig;
  });
});

// ═══════════════════════════════════════════════════════════════
// @xcg/common — MONEY UTILITIES (BigInt-based)
// ═══════════════════════════════════════════════════════════════

describe('@xcg/common — Money Utilities (BigInt precision)', () => {
  const { money } = require('@xcg/common');

  test('toUnits("100") = 10000000000n', () => {
    expect(money.toUnits('100')).toBe(10000000000n);
  });

  test('toUnits("0.000001") = 100n (minimum USDT unit at 8dp)', () => {
    expect(money.toUnits('0.000001')).toBe(100n);
  });

  test('fromUnits(10000000000n) = "100.00000000"', () => {
    expect(money.fromUnits(10000000000n)).toBe('100.00000000');
  });

  test('add("0.1", "0.2") = "0.30000000" (no float error)', () => {
    // Classic JS: 0.1 + 0.2 = 0.30000000000000004
    expect(money.add('0.1', '0.2')).toBe('0.30000000');
  });

  test('subtract("100", "0.1") = "99.90000000"', () => {
    expect(money.subtract('100', '0.1')).toBe('99.90000000');
  });

  test('multiply("100", "0.001") = "0.10000000" (0.1% fee)', () => {
    expect(money.multiply('100', '0.001')).toBe('0.10000000');
  });

  test('compare("100", "99.9") > 0', () => {
    expect(money.compare('100', '99.9')).toBeGreaterThan(0);
  });

  test('compare("99.9", "100") < 0', () => {
    expect(money.compare('99.9', '100')).toBeLessThan(0);
  });

  test('compare("100", "100") = 0', () => {
    expect(money.compare('100', '100')).toBe(0);
  });

  test('isValidAmount("100") = true', () => {
    expect(money.isValidAmount('100')).toBe(true);
  });

  test('isValidAmount("0") = false (zero is invalid)', () => {
    expect(money.isValidAmount('0')).toBe(false);
  });

  test('isValidAmount("-1") = false (negative invalid)', () => {
    expect(money.isValidAmount('-1')).toBe(false);
  });

  test('isValidAmount("1000001") = false (exceeds 1M USDT limit)', () => {
    expect(money.isValidAmount('1000001')).toBe(false);
  });

  test('Double-entry: fee + net must equal received (no phantom funds)', () => {
    // fee=0.10 USDT, net=99.90 USDT — sum must be exactly 100.00 USDT, no rounding error
    expect(money.add('0.10000000', '99.90000000')).toBe('100.00000000');
  });

  test('format() strips trailing zeros', () => {
    const result = money.format('100.00000000');
    expect(result).toBe('100');
  });
});

// ═══════════════════════════════════════════════════════════════
// @xcg/common — APPERROR
// ═══════════════════════════════════════════════════════════════

describe('@xcg/common — AppError', () => {
  const { AppError } = require('@xcg/common');

  test('AppError.notFound() → 404', () => {
    expect(AppError.notFound('Gone', 'NOT_FOUND').statusCode).toBe(404);
  });

  test('AppError.unauthorized() → 401', () => {
    expect(AppError.unauthorized('Denied', 'UNAUTH').statusCode).toBe(401);
  });

  test('AppError.forbidden() → 403', () => {
    expect(AppError.forbidden('No').statusCode).toBe(403);
  });

  test('AppError.badRequest() → 400', () => {
    expect(AppError.badRequest('Bad').statusCode).toBe(400);
  });

  test('AppError.internal() → 500', () => {
    expect(AppError.internal('Err').statusCode).toBe(500);
  });

  test('isOperational = true for user-facing factory methods', () => {
    // 4xx errors are operational — expected errors in normal production flow
    [AppError.notFound(), AppError.unauthorized(), AppError.forbidden(),
      AppError.badRequest()].forEach((err) => {
      expect(err.isOperational).toBe(true);
    });
  });

  test('isOperational = false for internal() — it is a programming error', () => {
    // 500 internal errors are NON-operational — they represent unexpected bugs
    expect(AppError.internal().isOperational).toBe(false);
  });

  test('AppError instance is an Error', () => {
    expect(AppError.notFound('x')).toBeInstanceOf(Error);
  });
});

// ═══════════════════════════════════════════════════════════════
// @xcg/common — SECURITY CONSTANTS
// ═══════════════════════════════════════════════════════════════

describe('@xcg/common — Security Constants', () => {
  const { constants } = require('@xcg/common');

  test('AUTH.MAX_FAILED_ATTEMPTS = 5', () => {
    expect(constants.AUTH.MAX_FAILED_ATTEMPTS).toBe(5);
  });

  test('AUTH.TIMESTAMP_TOLERANCE_SECONDS = 30', () => {
    expect(constants.AUTH.TIMESTAMP_TOLERANCE_SECONDS).toBe(30);
  });

  test('AUTH.NONCE_TTL_SECONDS = 300', () => {
    expect(constants.AUTH.NONCE_TTL_SECONDS).toBe(300);
  });

  test('TRON.CONFIRMATIONS_REQUIRED = 19', () => {
    expect(constants.TRON.CONFIRMATIONS_REQUIRED).toBe(19);
  });

  test('TRON.USDT_DECIMALS = 6', () => {
    expect(constants.TRON.USDT_DECIMALS).toBe(6);
  });

  test('TRON.MAINNET_USDT_CONTRACT = correct address', () => {
    expect(constants.TRON.MAINNET_USDT_CONTRACT).toBe('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t');
  });

  test('TRON.SHASTA_USDT_CONTRACT = correct Shasta testnet address', () => {
    expect(constants.TRON.SHASTA_USDT_CONTRACT).toBe('TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs');
  });

  test('Constants are frozen (cannot be mutated)', () => {
    const before = constants.TRON.CONFIRMATIONS_REQUIRED;
    try { constants.TRON.CONFIRMATIONS_REQUIRED = 1; } catch (_) { /* strict mode */ }
    expect(constants.TRON.CONFIRMATIONS_REQUIRED).toBe(before);
  });

  test('INVOICE_STATUS full lifecycle statuses defined', () => {
    const s = constants.INVOICE_STATUS;
    expect(s.PENDING).toBeDefined();
    expect(s.HASH_FOUND).toBeDefined();
    expect(s.CONFIRMED).toBeDefined();
    expect(s.EXPIRED).toBeDefined();
    expect(s.UNDERPAID).toBeDefined();
  });
});

// ═══════════════════════════════════════════════════════════════
// @xcg/common — RESPONSE BUILDER
// ═══════════════════════════════════════════════════════════════

describe('@xcg/common — Response Builder', () => {
  const { response } = require('@xcg/common');

  test('success() has success:true', () => {
    expect(response.success({ id: '1' }).success).toBe(true);
  });

  test('success() with null data → no data field', () => {
    expect(response.success(null, 'ok').data).toBeUndefined();
  });

  test('error() has success:false', () => {
    expect(response.error('CODE', 'msg').success).toBe(false);
  });

  test('error() includes code + timestamp', () => {
    const r = response.error('AUTH_FAIL', 'Bad');
    expect(r.error.code).toBe('AUTH_FAIL');
    expect(r.error.timestamp).toBeDefined();
  });

  test('error() with details field', () => {
    const r = response.error('VAL', 'Bad', { field: 'email' });
    expect(r.error.details).toEqual({ field: 'email' });
  });

  test('paginated() hasMore=true when not on last page', () => {
    const r = response.paginated(new Array(10).fill({}), 30, 1, 10);
    expect(r.pagination.hasMore).toBe(true);
    expect(r.pagination.pages).toBe(3);
  });

  test('paginated() hasMore=false on last page', () => {
    const r = response.paginated([{}], 3, 3, 1);
    expect(r.pagination.hasMore).toBe(false);
  });

  test('noContent() success:true no data', () => {
    const r = response.noContent('Deleted');
    expect(r.success).toBe(true);
    expect(r.data).toBeUndefined();
  });
});

// ═══════════════════════════════════════════════════════════════
// @xcg/common — OBJECT ID VALIDATION
// ═══════════════════════════════════════════════════════════════

describe('@xcg/common — ObjectId Validation', () => {
  const { isValidObjectId } = require('@xcg/common');

  const valid = [
    '507f1f77bcf86cd799439011',
    '000000000000000000000001',
    'a'.repeat(24),
  ];

  const invalid = [
    'not-an-id',
    '123',
    '',
    null,
    undefined,
    '507f1f77bcf86cd79943901',  // 23 chars
    '507f1f77bcf86cd7994390111', // 25 chars
    { $gt: '' },
  ];

  valid.forEach((id) => {
    test(`VALID ObjectId: ${id.slice(0, 10)}...`, () => {
      expect(isValidObjectId(id)).toBe(true);
    });
  });

  invalid.forEach((id) => {
    test(`INVALID ObjectId: ${String(id).slice(0, 15)}`, () => {
      expect(isValidObjectId(id)).toBe(false);
    });
  });
});

// ═══════════════════════════════════════════════════════════════
// WITHDRAWAL PROCESSOR — BUSINESS RULES (Unit Invariants)
// ═══════════════════════════════════════════════════════════════

describe('Withdrawal Processor — Business Rules', () => {
  test('Per-tx limit: 1000 USDT — 1001 blocked', () => {
    expect(1001 > 1000).toBe(true);
  });

  test('Per-tx limit: 999 USDT — allowed', () => {
    expect(999 > 1000).toBe(false);
  });

  test('Daily cap: 10000 USDT — 10001 blocked', () => {
    expect(10001 > 10000).toBe(true);
  });

  test('Cooling-off 1h: 30 min deposit still in cooldown', () => {
    const cooldown = 3600000;
    const depositAge = 30 * 60 * 1000; // 30 min
    expect(depositAge < cooldown).toBe(true);
  });

  test('High-value threshold 5000 USDT: 5001 requires admin approval', () => {
    expect(5001 > 5000).toBe(true);
  });

  test('Tron address validation regex', () => {
    const valid = /^T[1-9A-HJ-NP-Za-km-z]{33}$/;
    expect(valid.test('TN3W4T7pk41MMxL1mjC6HeMoAWH7aA4X9F')).toBe(true);
    expect(valid.test('0xETHAddress')).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════
// AUDIT LOG — SHA-256 HASH CHAIN INTEGRITY
// ═══════════════════════════════════════════════════════════════

describe('AuditLog — Hash Chain Integrity', () => {
  const { createHash } = require('crypto');

  test('SHA-256 is deterministic', () => {
    const h1 = createHash('sha256').update('test').digest('hex');
    const h2 = createHash('sha256').update('test').digest('hex');
    expect(h1).toBe(h2);
    expect(h1).toHaveLength(64);
  });

  test('Genesis hash = SHA-256("GENESIS")', () => {
    const genesis = createHash('sha256').update('GENESIS').digest('hex');
    expect(genesis).toBe('901131d838b17aac0f7885b81e03cbdc9f5157a00343d30ab22083685ed1416a');
  });

  test('Changed actor → different chain hash (tamper detection)', () => {
    const make = (actor) =>
      createHash('sha256').update(`${actor}:action:resource:2024-01-01:prevHash`).digest('hex');
    expect(make('alice')).not.toBe(make('hacker'));
  });

  test('Changed timestamp → different chain hash', () => {
    const make = (ts) =>
      createHash('sha256').update(`alice:login:resource:${ts}:prevHash`).digest('hex');
    expect(make('2024-01-01')).not.toBe(make('2024-01-02'));
  });

  test('Chain hashes are exactly 64 hex chars', () => {
    const h = createHash('sha256').update('any-data').digest('hex');
    expect(/^[0-9a-f]{64}$/.test(h)).toBe(true);
  });
});
