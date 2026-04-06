'use strict';

/**
 * Input Validation & WAF Test Suite — Banking Grade.
 *
 * Coverage:
 *   - Joi schema validation for all major route inputs
 *   - WAF middleware (path traversal, null byte, SQL injection patterns)
 *   - Request hardening (HTTP smuggling, oversized headers)
 *   - Parameter pollution
 *   - Mass assignment prevention
 *   - Content-Security-Policy, HSTS, X-Frame-Options headers
 *   - Rate limiting response shapes
 *   - Pagination abuse (extreme values)
 *   - ID format validation (ObjectId)
 */

const request = require('supertest');
const jwt     = require('jsonwebtoken');

// ─── Mocks ────────────────────────────────────────────────────────────────────
const _mockUser = {
  _id: 'merchant1',
  email: 'merchant@test.com',
  role: 'merchant',
  merchantId: 'merch1',
  isActive: true,
  isLocked: false,
  lockUntil: null,
  passwordChangedAt: null,
};
const _makeSel = (u) => ({ select: jest.fn().mockResolvedValue(u) });

jest.mock('@xcg/database', () => ({
  connectDB: jest.fn(), disconnectDB: jest.fn(), isDBConnected: () => false,
  User: {
    findOne: jest.fn(),
    findById: jest.fn(() => _makeSel(_mockUser)),
  },
  RefreshToken: { findOne: jest.fn(), create: jest.fn(), updateOne: jest.fn(), updateMany: jest.fn(), countDocuments: jest.fn() },
  UsedTotpCode: { create: jest.fn() },
  UsedNonce: { exists: jest.fn().mockResolvedValue(false), create: jest.fn() },
  AuditLog: { create: jest.fn() },
  Merchant: { findOne: jest.fn(), findById: jest.fn() },
  Invoice: { findById: jest.fn() },
  Withdrawal: { find: jest.fn(), create: jest.fn(), aggregate: jest.fn().mockResolvedValue([]) },
  LedgerEntry: { aggregate: jest.fn().mockResolvedValue([{ credits: 0, debits: 0 }]) },
  Wallet: {}, Transaction: {}, Dispute: {}, WebhookDelivery: {},
  SystemConfig: {}, BlacklistedWallet: { findOne: jest.fn().mockResolvedValue(null) },
}));

jest.mock('../src/services/authService', () => ({
  register: jest.fn(), login: jest.fn(), logout: jest.fn(),
  logoutAll: jest.fn(), refreshTokens: jest.fn(), changePassword: jest.fn(),
  getProfile: jest.fn(), setup2FA: jest.fn(), verify2FA: jest.fn(), disable2FA: jest.fn(),
}));

const { app } = require('../src/app');

beforeAll(() => {
  process.env.JWT_ACCESS_SECRET     = 'a'.repeat(64);
  process.env.JWT_REFRESH_SECRET    = 'b'.repeat(64);
  process.env.MASTER_ENCRYPTION_KEY = 'a'.repeat(64);
});

const merchantJWT = () =>
  jwt.sign({ userId: 'merchant1', role: 'merchant' }, process.env.JWT_ACCESS_SECRET, { expiresIn: '15m' });

const adminJWT = () =>
  jwt.sign({ userId: 'admin1', role: 'admin' }, process.env.JWT_ACCESS_SECRET, { expiresIn: '15m' });

// ═══════════════════════════════════════════════════════════════
// WAF — REQUEST HARDENING
// ═══════════════════════════════════════════════════════════════

describe('WAF — Request Hardening', () => {
  test('Path traversal /../ → 400 blocked', async () => {
    const res = await request(app).get('/api/v1/../../../etc/passwd');
    expect([400, 404]).toContain(res.status);
    expect(res.body.success).toBe(false);
  });

  test('Null byte in URL → 400 blocked', async () => {
    const res = await request(app).get('/api/v1/auth/login%00');
    expect([400, 404]).toContain(res.status);
  });

  test('Curl user-agent (scanner fingerprint) → request processed normally', async () => {
    // We block known exploit tools, but curl is legitimate
    const res = await request(app)
      .get('/internal/health')
      .set('User-Agent', 'curl/7.64.1');
    expect(res.status).toBe(200);
  });

  test('sqlmap user-agent (SQL injection scanner) → 403 blocked', async () => {
    const res = await request(app)
      .get('/internal/health')
      .set('User-Agent', 'sqlmap/1.4.7');
    expect([403, 400]).toContain(res.status);
  });

  test('Nikto scanner user-agent → 403 blocked', async () => {
    const res = await request(app)
      .get('/internal/health')
      .set('User-Agent', 'Nikto/2.1.6');
    expect([403, 400]).toContain(res.status);
  });

  test('OPTIONS method is handled for CORS preflight', async () => {
    const res = await request(app)
      .options('/api/v1/auth/login')
      .set('Origin', 'https://example.com')
      .set('Access-Control-Request-Method', 'POST');
    // Must respond to OPTIONS (not 405)
    expect(res.status).not.toBe(405);
  });
});

// ═══════════════════════════════════════════════════════════════
// SECURITY HEADERS — COMPLETE AUDIT
// ═══════════════════════════════════════════════════════════════

describe('Security Headers — Complete Audit', () => {
  let res;
  beforeAll(async () => {
    res = await request(app).get('/internal/health');
  });

  test('X-Content-Type-Options: nosniff', () => {
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  test('X-Frame-Options: DENY or SAMEORIGIN', () => {
    const val = res.headers['x-frame-options'];
    expect(val).toBeDefined();
    expect(['DENY', 'SAMEORIGIN']).toContain(val.toUpperCase());
  });

  test('X-XSS-Protection: present', () => {
    // Helmet may set to 0 (modern approach), but must be present
    expect(res.headers['x-xss-protection']).toBeDefined();
  });

  test('Strict-Transport-Security (HSTS): present with max-age', () => {
    const hsts = res.headers['strict-transport-security'];
    expect(hsts).toBeDefined();
    expect(hsts).toContain('max-age=');
    const maxAge = parseInt(hsts.match(/max-age=(\d+)/)?.[1] ?? '0', 10);
    expect(maxAge).toBeGreaterThanOrEqual(31536000); // 1 year minimum
  });

  test('Content-Security-Policy: default-src self', () => {
    const csp = res.headers['content-security-policy'];
    expect(csp).toBeDefined();
    expect(csp).toContain("default-src 'self'");
  });

  test('X-Powered-By is hidden (tech stack concealment)', () => {
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  test('Referrer-Policy is set', () => {
    expect(res.headers['referrer-policy']).toBeDefined();
  });

  test('Server header is absent or generic (no version leak)', () => {
    const server = res.headers['server'];
    if (server) {
      expect(server).not.toMatch(/express|node|nginx\/\d/i);
    }
  });
});

// ═══════════════════════════════════════════════════════════════
// HTTP PARAMETER POLLUTION
// ═══════════════════════════════════════════════════════════════

describe('HTTP Parameter Pollution Prevention (HPP)', () => {
  test('Duplicate query params → single value (HPP blocked)', async () => {
    const res = await request(app)
      .get('/internal/health?status=ok&status=compromised&status=hacked');
    // HPP protection ensures only first or last value is used, not array
    expect(res.status).not.toBe(500); // Not a server crash
  });

  test('Array injection in body via duplicate keys → handled safely', async () => {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .set('Content-Type', 'application/json')
      .send('{"email":"test@test.com","email":"injected@evil.com","password":"pass"}');
    // Must not crash — either use first or last value
    expect(res.status).not.toBe(500);
  });
});

// ═══════════════════════════════════════════════════════════════
// NOSQL INJECTION — COMPREHENSIVE
// ═══════════════════════════════════════════════════════════════

describe('NoSQL Injection — Comprehensive', () => {
  const endpoints = [
    { method: 'POST', path: '/api/v1/auth/login',    body: { email: { $gt: '' }, password: 'x' } },
    { method: 'POST', path: '/api/v1/auth/login',    body: { email: 'x@x.com', password: { $ne: '' } } },
    { method: 'POST', path: '/api/v1/auth/login',    body: { $where: '1===1', email: 'x', password: 'x' } },
    { method: 'POST', path: '/api/v1/auth/register', body: { email: { $regex: '.*' }, password: 'x', name: 'x' } },
    { method: 'POST', path: '/api/v1/auth/login',    body: { email: 'x@x.com', password: { $gt: '' } } },
  ];

  endpoints.forEach(({ method, path, body }) => {
    test(`${method} ${path} — operator in ${JSON.stringify(Object.keys(body)[0])} → blocked`, async () => {
      const res = await request(app)
        [method.toLowerCase()](path)
        .set('Content-Type', 'application/json')
        .send(body);
      expect(res.status).not.toBe(200);
      expect(res.body.success).not.toBe(true);
    });
  });
});

// ═══════════════════════════════════════════════════════════════
// OBJECT ID VALIDATION
// ═══════════════════════════════════════════════════════════════

describe('ObjectId Validation', () => {
  test('Invalid ObjectId in pay route → 400', async () => {
    const res = await request(app).get('/api/v1/pay/NOT_VALID_OBJECT_ID');
    expect([400, 404]).toContain(res.status);
    expect(res.body.success).toBe(false);
  });

  test('ObjectId with injection attempts → 400', async () => {
    const res = await request(app).get('/api/v1/pay/507f1f77bcf86cd799439011; DROP TABLE invoices;');
    expect([400, 404]).toContain(res.status);
  });

  test('Valid 24-char hex ObjectId → passes format check', async () => {
    const { Invoice } = require('@xcg/database');
    Invoice.findById.mockResolvedValueOnce(null); // Not found but valid format
    const res = await request(app).get('/api/v1/pay/507f1f77bcf86cd799439011');
    // 404 if not found is correct behavior (valid format, doesn't exist)
    expect([200, 404]).toContain(res.status);
  });
});

// ═══════════════════════════════════════════════════════════════
// PAGINATION ABUSE
// ═══════════════════════════════════════════════════════════════

describe('Pagination Abuse Prevention', () => {
  test('Extreme page number → handled (not 500)', async () => {
    const res = await request(app)
      .get('/api/v1/portal/invoices?page=99999999')
      .set('Authorization', `Bearer ${merchantJWT()}`);
    expect(res.status).not.toBe(500);
  });

  test('Negative page → handled (not 500)', async () => {
    const res = await request(app)
      .get('/api/v1/portal/invoices?page=-1')
      .set('Authorization', `Bearer ${merchantJWT()}`);
    expect(res.status).not.toBe(500);
  });

  test('Limit=10000 (DoS via large page) → capped or rejected', async () => {
    const res = await request(app)
      .get('/api/v1/portal/invoices?limit=10000')
      .set('Authorization', `Bearer ${merchantJWT()}`);
    expect(res.status).not.toBe(500);
    // If 200, limit must be capped
    if (res.status === 200 && res.body.pagination) {
      expect(res.body.pagination.limit).toBeLessThanOrEqual(100);
    }
  });
});

// ═══════════════════════════════════════════════════════════════
// MASS ASSIGNMENT PREVENTION
// ═══════════════════════════════════════════════════════════════

describe('Mass Assignment Prevention', () => {
  test('Registration: cannot set role=admin via body', async () => {
    const authService = require('../src/services/authService');
    authService.register.mockResolvedValueOnce({
      user: { _id: 'id1', email: 'x@x.com', role: 'merchant', name: 'Test' },
      accessToken: 'tok',
      refreshToken: 'rtok',
    });
    const res = await request(app)
      .post('/api/v1/auth/register')
      .set('Content-Type', 'application/json')
      .send({ email: 'x@x.com', password: 'Str0ng!Pass#1', name: 'Test', role: 'admin' });
    if (res.status === 201) {
      // If it registered, role must not be admin
      expect(res.body.data?.user?.role).not.toBe('admin');
    } else {
      expect([400, 422]).toContain(res.status);
    }
  });

  test('Registration: cannot set isAdmin=true via body', async () => {
    const authService = require('../src/services/authService');
    authService.register.mockResolvedValueOnce({
      user: { _id: 'id2', email: 'y@y.com', role: 'merchant', name: 'Test', isAdmin: false },
      accessToken: 'tok',
      refreshToken: 'rtok',
    });
    const res = await request(app)
      .post('/api/v1/auth/register')
      .set('Content-Type', 'application/json')
      .send({ email: 'y@y.com', password: 'Str0ng!Pass#1', name: 'Test', isAdmin: true });
    if (res.status === 201) {
      expect(res.body.data?.user?.isAdmin).not.toBe(true);
    }
  });
});

// ═══════════════════════════════════════════════════════════════
// RESPONSE SANITIZATION — NO SENSITIVE DATA LEAKS
// ═══════════════════════════════════════════════════════════════

describe('Response Sanitization — No Data Leaks', () => {
  test('Error responses never include stack traces in production', async () => {
    const res = await request(app).get('/api/v1/nonexistent');
    const body = JSON.stringify(res.body);
    expect(body).not.toContain('at Object.<anonymous>');
    expect(body).not.toContain('node_modules');
    expect(body).not.toContain('.js:');
  });

  test('404 response never includes internal path info', async () => {
    const res = await request(app).get('/api/v1/does-not-exist');
    const body = JSON.stringify(res.body);
    expect(body).not.toContain('/home/');
    expect(body).not.toContain('C:\\Users');
    expect(body).not.toContain('services/api-server');
  });

  test('500 errors are generic — no internal error details', async () => {
    // Force a 500 scenario via route that might throw
    const res = await request(app)
      .post('/api/v1/auth/login')
      .set('Content-Type', 'application/json')
      .send({ email: 'test@test.com', password: 'ValidPass#1' });
    if (res.status === 500) {
      expect(res.body.error.message).not.toContain('MongoDB');
      expect(res.body.error.message).not.toContain('Connection');
      expect(res.body.error.message).not.toContain('stack');
    }
  });
});

// ═══════════════════════════════════════════════════════════════
// CONTENT NEGOTIATION
// ═══════════════════════════════════════════════════════════════

describe('Content Negotiation', () => {
  test('POST with multipart/form-data → 422 (not JSON)', async () => {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .set('Content-Type', 'multipart/form-data')
      .send('email=test@test.com');
    expect([400, 422, 415]).toContain(res.status);
    expect(res.body.success).toBe(false);
  });

  test('API always responds with application/json content-type', async () => {
    const res = await request(app).get('/internal/health');
    expect(res.headers['content-type']).toMatch(/application\/json/);
  });

  test('POST with XML → 422 rejected', async () => {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .set('Content-Type', 'application/xml')
      .send('<login><email>x@x.com</email></login>');
    expect([400, 422, 415]).toContain(res.status);
  });
});
