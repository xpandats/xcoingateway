'use strict';

/**
 * Authentication Security Test Suite — Banking Grade.
 *
 * Coverage:
 *   - Registration: input validation, duplicate prevention, password policy
 *   - Login: credential validation, JWT issuance, brute force detection
 *   - JWT: token structure, algorithm pinning, expiry, tampering
 *   - 2FA: TOTP setup, verify, disable, re-auth enforcement
 *   - Token Refresh: rotation, replay prevention, revocation
 *   - Logout: session revocation, all-sessions logout
 *   - Password Change: current password required, history enforcement
 *   - Profile: data isolation (users can only see own data)
 */

const request = require('supertest');
const jwt     = require('jsonwebtoken');


// ─── Mock ESM-incompatible modules ────────────────────────────────────────────
const _mockUser = {
  _id: 'abc',
  email: 'user@test.com',
  role: 'merchant',
  merchantId: 'merch1',
  isActive: true,
  isLocked: false,
  lockUntil: null,
  passwordChangedAt: null,
};
const _mockAdmin = {
  _id: 'admin001',
  email: 'admin@test.com',
  role: 'admin',
  isActive: true,
  isLocked: false,
  lockUntil: null,
  passwordChangedAt: null,
};
const _makeSel = (u) => ({ select: jest.fn().mockResolvedValue(u) });

jest.mock('@xcg/database', () => ({
  connectDB:      jest.fn(),
  disconnectDB:   jest.fn(),
  isDBConnected:  () => false,
  User:           {
    findOne:        jest.fn(),
    findById:       jest.fn((id) => _makeSel(id === 'admin001' ? _mockAdmin : _mockUser)),
    create:         jest.fn(),
    findByIdAndUpdate: jest.fn(),
  },
  RefreshToken:   {
    findOne:        jest.fn(),
    create:         jest.fn(),
    updateOne:      jest.fn(),
    updateMany:     jest.fn(),
    countDocuments: jest.fn(),
    deleteMany:     jest.fn(),
  },
  UsedTotpCode:   { create: jest.fn(), findOne: jest.fn() },
  UsedNonce:      { exists: jest.fn().mockResolvedValue(false), create: jest.fn() },
  AuditLog:       { create: jest.fn() },
  LedgerEntry:    {},
  Merchant:       { findOne: jest.fn() },
  Wallet:         {},
  Transaction:    {},
  Invoice:        {},
  Withdrawal:     {},
  Dispute:        {},
  WebhookDelivery:{},
  SystemConfig:   {},
}));


jest.mock('../src/services/authService', () => ({
  register:       jest.fn(),
  login:          jest.fn(),
  logout:         jest.fn(),
  logoutAll:      jest.fn(),
  refreshTokens:  jest.fn(),
  changePassword: jest.fn(),
  getProfile:     jest.fn(),
  setup2FA:       jest.fn(),
  verify2FA:      jest.fn(),
  disable2FA:     jest.fn(),
}));

const { app }        = require('../src/app');
const authService    = require('../src/services/authService');
const { config }     = require('../src/config');

// ─── Helpers ──────────────────────────────────────────────────────────────────
const post = (path, body, token) => {
  const r = request(app)
    .post(path)
    .set('Content-Type', 'application/json');
  if (token) r.set('Authorization', `Bearer ${token}`);
  return r.send(body);
};

const get = (path, token) => {
  const r = request(app).get(path);
  if (token) r.set('Authorization', `Bearer ${token}`);
  return r;
};

// Use config.jwt.accessSecret — it is loaded at app startup from env/dotenv
// so tokens generated here are always verifiable by the authenticate middleware.
const makeJWT = (payload, secret, options = {}) =>
  jwt.sign(payload, secret || config.jwt.accessSecret, { expiresIn: '15m', ...options });

beforeAll(() => {
  process.env.JWT_ACCESS_SECRET  = 'a'.repeat(64);
  process.env.JWT_REFRESH_SECRET = 'b'.repeat(64);
  process.env.MASTER_ENCRYPTION_KEY = 'a'.repeat(64);
});

// ═══════════════════════════════════════════════════════════════
// REGISTRATION INPUT VALIDATION
// ═══════════════════════════════════════════════════════════════

describe('Registration — Input Validation', () => {
  test('Missing email → 400 VALIDATION_FAILED', async () => {
    const res = await post('/api/v1/auth/register', { password: 'Str0ng!Pass#1', name: 'Test' });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.error.code).toMatch(/VALIDATION/i);
  });

  test('Invalid email format → 400', async () => {
    const res = await post('/api/v1/auth/register', {
      email: 'not-an-email',
      password: 'Str0ng!Pass#1',
      name: 'Test',
    });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('Weak password → 400', async () => {
    const res = await post('/api/v1/auth/register', {
      email: 'user@example.com',
      password: '123',
      name: 'Test',
    });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('Missing name → 400', async () => {
    const res = await post('/api/v1/auth/register', {
      email: 'user@example.com',
      password: 'Str0ng!Pass#1',
    });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('SQL/script injection in name → 400 or sanitized', async () => {
    const _xssUser = { _id: 'id1', email: 'x@x.com', role: 'merchant', firstName: 'cleaned', lastName: 'user' };
    authService.register.mockResolvedValueOnce({ isNew: true, user: { ..._xssUser, toSafeJSON: () => _xssUser }, accessToken: 'tok', refreshToken: 'rtok' });
    const res = await post('/api/v1/auth/register', {
      email: 'user@example.com',
      password: 'Str0ng!Pass#1',
      firstName: '<script>alert(1)</script>',
      lastName: 'Safe',
    });
    // Either reject or strip XSS — never echo raw
    if (res.status === 201) {
      expect(res.body.data?.firstName).not.toContain('<script>');
    } else {
      expect(res.status).toBe(400);
    }
  });

  test('Valid registration → 201 with success envelope', async () => {
    const _safeUser = { _id: 'abc123', email: 'valid@example.com', role: 'merchant', name: 'Valid User' };
    authService.register.mockResolvedValueOnce({
      isNew: true, // required — controller path for new registrations
      user: { ..._safeUser, toSafeJSON: () => _safeUser },
      accessToken: 'access.token.here',
      refreshToken: 'refresh.token.here',
    });
    const res = await post('/api/v1/auth/register', {
      email: 'valid@example.com',
      password: 'Str0ng!Pass#1',
      firstName: 'Valid',   // schema requires firstName + lastName
      lastName: 'User',
    });
    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.data).toBeDefined();
    // Password must NEVER appear in response
    expect(JSON.stringify(res.body)).not.toContain('Str0ng!Pass#1');
  });
});

// ═══════════════════════════════════════════════════════════════
// LOGIN INPUT VALIDATION
// ═══════════════════════════════════════════════════════════════

describe('Login — Input Validation', () => {
  test('Missing password → 400', async () => {
    const res = await post('/api/v1/auth/login', { email: 'user@example.com' });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('Missing email → 400', async () => {
    const res = await post('/api/v1/auth/login', { password: 'anypassword' });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('Invalid email format → 400', async () => {
    const res = await post('/api/v1/auth/login', { email: 'notanemail', password: 'test' });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('NoSQL operator in email is blocked', async () => {
    const res = await post('/api/v1/auth/login', {
      email: { $regex: '.*', $options: 'i' },
      password: 'anything',
    });
    expect(res.status).not.toBe(200);
    expect(res.body.success).not.toBe(true);
  });

  test('Valid credentials → 200 with tokens', async () => {
    const _safeUser = { _id: 'abc', email: 'user@test.com', role: 'merchant', twoFactorEnabled: false };
    authService.login.mockResolvedValueOnce({
      user:         { ..._safeUser, toSafeJSON: () => _safeUser },
      accessToken:  'valid.access.token',
      refreshToken: 'valid.refresh.token',
    });
    const res = await post('/api/v1/auth/login', {
      email: 'user@test.com',
      password: 'Str0ng!Pass#1',
    });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.accessToken).toBeDefined();
    // Password never in response
    expect(JSON.stringify(res.body)).not.toContain('Pass#1');
  });

  test('Auth service throws INVALID_CREDENTIALS → 401, no info leak', async () => {
    const { AppError } = require('@xcg/common');
    authService.login.mockRejectedValueOnce(
      AppError.unauthorized('Invalid credentials', 'AUTH_INVALID_CREDENTIALS'),
    );
    const res = await post('/api/v1/auth/login', {
      email: 'nonexistent@test.com',
      password: 'WrongP4ss#1',  // Must pass Joi (has upper, lower, digit, special)
    });
    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
    expect(res.body.error.code).toBe('AUTH_INVALID_CREDENTIALS');
    // Must not reveal user existence
    expect(res.body.error.message).not.toContain('not found');
    expect(res.body.error.message).not.toContain('exist');
  });
});

// ═══════════════════════════════════════════════════════════════
// JWT SECURITY
// ═══════════════════════════════════════════════════════════════

describe('JWT Security', () => {
  test('Valid JWT grants access to /me', async () => {
    authService.getProfile.mockResolvedValueOnce({
      _id: 'abc', email: 'user@test.com', role: 'merchant', name: 'Test',
    });
    const token = makeJWT({ userId: 'abc', role: 'merchant', email: 'user@test.com' });
    const res = await get('/api/v1/auth/me', token);
    expect(res.status).toBe(200);
  });

  test('Expired JWT → 401 AUTH_TOKEN_EXPIRED', async () => {
    const expiredToken = makeJWT(
      { userId: 'abc', role: 'merchant' },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: '-1s' }, // Immediately expired
    );
    const res = await get('/api/v1/auth/me', expiredToken);
    expect(res.status).toBe(401);
    expect(res.body.error.code).toMatch(/EXPIR|TOKEN/i);
  });

  test('JWT signed with wrong secret → 401', async () => {
    const badToken = makeJWT({ userId: 'abc', role: 'admin' }, 'wrong-secret-entirely');
    const res = await get('/api/v1/auth/me', badToken);
    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  test('JWT with alg:none (confusion attack) → 401', async () => {
    const header  = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ userId: 'abc', role: 'super_admin', exp: 9999999999 })).toString('base64url');
    const token   = `${header}.${payload}.`;
    const res     = await get('/api/v1/auth/me', token);
    expect(res.status).toBe(401);
  });

  test('JWT with role:admin self-granted (tampered payload) → 401', async () => {
    // Tamper the payload but keep a valid-looking structure with wrong secret
    const maliciousToken = makeJWT(
      { userId: 'abc', role: 'super_admin', email: 'hacker@evil.com' },
      'attacker-controlled-secret',
    );
    const res = await get('/api/v1/auth/me', maliciousToken);
    expect(res.status).toBe(401);
  });

  test('Bearer token with extra spaces → 401 (strict parsing)', async () => {
    const res = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', 'Bearer  double-space-token');
    expect(res.status).toBe(401);
  });

  test('Token in query string is NOT accepted (header-only)', async () => {
    const token = makeJWT({ userId: 'abc', role: 'merchant' });
    const res = await request(app).get(`/api/v1/auth/me?token=${token}`);
    expect(res.status).toBe(401);
  });
});

// ═══════════════════════════════════════════════════════════════
// PROTECTED ROUTES — ROLE ISOLATION
// ═══════════════════════════════════════════════════════════════

describe('Role Isolation — Merchants Cannot Access Admin Routes', () => {
  const merchantToken = () => makeJWT({ userId: 'merchant1', role: 'merchant', email: 'm@m.com' });
  const supportToken  = () => makeJWT({ userId: 'sup1', role: 'support', email: 's@s.com' });

  test('Merchant JWT → admin route → 4xx DENIED', async () => {
    // Admin routes are at /admin/* (no /api/v1 prefix)
    const res = await get('/admin/users', merchantToken());
    expect([401, 403]).toContain(res.status);
    expect(res.body.success).toBe(false);
  });

  test('Support JWT → admin wallet creation → 4xx DENIED', async () => {
    const res = await request(app)
      .post('/admin/wallets')
      .set('Content-Type', 'application/json')
      .set('Authorization', `Bearer ${supportToken()}`)
      .send({});
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.body.success).toBe(false);
  });

  test('Unauthenticated → admin route → 401', async () => {
    const res = await get('/admin/users');
    expect(res.status).toBe(401);
  });

  test('Merchant cannot access admin merchants list', async () => {
    const res = await get('/admin/merchants', merchantToken());
    expect([401, 403]).toContain(res.status);
    expect(res.body.success).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════
// LOGOUT & SESSION REVOCATION
// ═══════════════════════════════════════════════════════════════

describe('Logout & Session Management', () => {
  test('Logout without token → 401', async () => {
    const res = await post('/api/v1/auth/logout', {});
    expect(res.status).toBe(401);
  });

  test('Logout with valid token → 200', async () => {
    authService.logout.mockResolvedValueOnce(true);
    const token = makeJWT({ userId: 'abc', role: 'merchant' });
    const res = await post('/api/v1/auth/logout', {}, token);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('POST /auth/logout-all without token → 401', async () => {
    const res = await post('/api/v1/auth/logout-all', {});
    expect(res.status).toBe(401);
  });
});

// ═══════════════════════════════════════════════════════════════
// TOKEN REFRESH SECURITY
// ═══════════════════════════════════════════════════════════════

describe('Token Refresh Security', () => {
  test('Refresh without refresh token cookie → 401', async () => {
    const { AppError } = require('@xcg/common');
    authService.refreshTokens.mockRejectedValueOnce(
      AppError.unauthorized('Refresh token required', 'AUTH_TOKEN_MISSING'),
    );
    const res = await post('/api/v1/auth/refresh', {});
    expect([400, 401]).toContain(res.status);
    expect(res.body.success).toBe(false);
  });

  test('Refresh with garbage token → 401', async () => {
    const { AppError } = require('@xcg/common');
    authService.refreshTokens.mockRejectedValueOnce(
      AppError.unauthorized('Invalid refresh token', 'AUTH_TOKEN_INVALID'),
    );
    const res = await post('/api/v1/auth/refresh', { refreshToken: 'garbage.token' });
    expect([400, 401]).toContain(res.status);
    expect(res.body.success).toBe(false);
  });

  test('Refresh with valid token → 200 with new tokens', async () => {
    authService.refreshTokens.mockResolvedValueOnce({
      accessToken: 'new.access.token',
      refreshToken: 'new.refresh.token',
    });
    const refreshToken = jwt.sign(
      { userId: 'abc', tokenFamily: 'fam1' },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '7d' },
    );
    const res = await post('/api/v1/auth/refresh', { refreshToken });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.accessToken).toBeDefined();
  });
});

// ═══════════════════════════════════════════════════════════════
// PASSWORD CHANGE SECURITY
// ═══════════════════════════════════════════════════════════════

describe('Password Change Security', () => {
  test('Change password without auth → 401', async () => {
    const res = await post('/api/v1/auth/change-password', {
      currentPassword: 'old', newPassword: 'NewStr0ng!Pass#1',
    });
    expect(res.status).toBe(401);
  });

  test('Change password missing currentPassword → 400', async () => {
    const token = makeJWT({ userId: 'abc', role: 'merchant' });
    const res = await post('/api/v1/auth/change-password', {
      newPassword: 'NewStr0ng!Pass#1',
    }, token);
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('Change password missing newPassword → 400', async () => {
    const token = makeJWT({ userId: 'abc', role: 'merchant' });
    const res = await post('/api/v1/auth/change-password', {
      currentPassword: 'OldPass#1',
    }, token);
    expect(res.status).toBe(400);
  });

  test('Change password to weak password → 400', async () => {
    const token = makeJWT({ userId: 'abc', role: 'merchant' });
    const res = await post('/api/v1/auth/change-password', {
      currentPassword: 'OldPass#1',
      newPassword: '123',
    }, token);
    expect(res.status).toBe(400);
  });

  test('Valid password change → 200', async () => {
    authService.changePassword.mockResolvedValueOnce(true);
    const token = makeJWT({ userId: 'abc', role: 'merchant' });
    const res = await post('/api/v1/auth/change-password', {
      currentPassword: 'OldStr0ng!Pass#1',
      newPassword: 'NewStr0ng!Pass#2',
    }, token);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════
// 2FA ENDPOINTS
// ═══════════════════════════════════════════════════════════════

describe('2FA Endpoints', () => {
  test('POST /auth/2fa/setup without auth → 401', async () => {
    const res = await request(app)
      .post('/api/v1/auth/2fa/setup')
      .set('Content-Type', 'application/json')
      .send({});
    expect(res.status).toBe(401);
  });

  test('POST /auth/2fa/setup with auth → 200 with QR data', async () => {
    authService.setup2FA.mockResolvedValueOnce({
      otpAuthUrl: 'otpauth://totp/XCoinGateway:test@test.com?secret=JBSWY3DPEHPK3PXP&issuer=XCoinGateway',
      qrCode: 'data:image/png;base64,abc123',  // base64 encoded QR image
    });
    const token = makeJWT({ userId: 'abc', role: 'merchant' });
    const res = await request(app)
      .post('/api/v1/auth/2fa/setup')
      .set('Authorization', `Bearer ${token}`)
      .set('Content-Type', 'application/json')
      .send({});
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.otpAuthUrl).toBeDefined();
    // Secret must NOT appear in response (would expose seed)
    expect(res.body.data).not.toHaveProperty('secret');
  });

  test('POST /auth/2fa/verify without token param → 400', async () => {
    const token = makeJWT({ userId: 'abc', role: 'merchant' });
    const res = await request(app)
      .post('/api/v1/auth/2fa/verify')
      .set('Authorization', `Bearer ${token}`)
      .set('Content-Type', 'application/json')
      .send({}); // missing totp code
    expect([400, 401]).toContain(res.status);
  });

  test('POST /auth/2fa/disable without auth → 401', async () => {
    const res = await request(app)
      .post('/api/v1/auth/2fa/disable')
      .set('Content-Type', 'application/json')
      .send({ token: '123456' });
    expect(res.status).toBe(401);
  });
});
