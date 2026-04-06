'use strict';

/**
 * @module services/api-server/app
 *
 * Express Application — Bank-Grade Security-Hardened.
 *
 * Middleware stack (applied in strict order — ORDER IS CRITICAL):
 *   1.  Helmet           — Security headers (XSS, clickjacking, HSTS)
 *   2.  CORS             — Strict origin whitelist
 *   3.  Rate Limiting    — General + auth-specific limiters
 *   4.  Body Parser      — Strict size limits (prevents DoS)
 *   5.  Content-Type     — Enforce JSON for mutation requests
 *   6.  NoSQL Sanitize   — Strip MongoDB operators (AFTER body parser)
 *   7.  HPP              — HTTP Parameter Pollution prevention
 *   8.  Cookie Parser    — Parse HTTP-only cookies
 *   9.  Request ID       — Inject unique tracing ID
 *   10. Request Context  — AsyncLocalStorage propagation (AFTER requestId)
 *   11. Request Logging  — Structured access log
 *   12. Routes           — Business logic
 *   13. 404 Handler      — Catch unmapped routes
 *   14. Error Handler    — Centralized error serialization
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');

const { noSqlSanitize } = require('./middleware/noSqlSanitize');
const { requestHardening } = require('./middleware/requestHardening');
const { randomUUID } = require('crypto');

const { createLogger } = require('@xcg/logger');
const { AppError, HttpStatus, response, requestContextMiddleware } = require('@xcg/common');
const { config } = require('./config');
const { validateOrigin } = require('./middleware/originValidation');
const { ipAuthLimiter, ipMerchantLimiter, ipGeneralLimiter } = require('./middleware/ipRateLimit');


// H2: Attempt to use Redis store for rate limiting (survives restarts, works across instances)
// Falls back to in-memory store if Redis is unavailable (safe for single-instance dev)
// SECURITY: hmacNonceRedis is also injected into merchant API route factories for
// atomic nonce deduplication (SET NX). Must be module-level, not scoped inside try.
let rateLimitStore;
let hmacNonceRedis = null;  // Promoted to module scope — used by invoice + withdrawal routes
try {
  const RedisStore = require('rate-limit-redis');
  const { createClient } = require('redis');
  const redisClient = createClient({ url: config.redis.url });
  redisClient.connect().catch(() => {}); // Non-blocking connect
  rateLimitStore   = new RedisStore({ sendCommand: (...args) => redisClient.sendCommand(args) });
  hmacNonceRedis   = redisClient; // Share same connection for nonce dedup (atomic SET NX)
} catch {
  // rate-limit-redis not installed or Redis unavailable — use in-memory (dev only)
  rateLimitStore = undefined;
  hmacNonceRedis = null;
}



// ─── Route Imports ───────────────────────────────────────────────────────────
const authRoutes             = require('./routes/auth');
const healthRoutes           = require('./routes/health');
const walletRoutes           = require('./routes/wallets');
const merchantRoutes         = require('./routes/merchants');
const adminRoutes            = require('./routes/admin');
const adminUsersRoutes       = require('./routes/adminUsers');
const adminSystemRoutes      = require('./routes/adminSystem');
const adminWebhooksRoutes    = require('./routes/adminWebhooks');
const adminReconRoutes       = require('./routes/adminReconciliation');
const supportRoutes          = require('./routes/support');
const merchantPortalRoutes   = require('./routes/merchantPortal');
const publicPayRoutes        = require('./routes/publicPay');
// Factory routes — redisClient injected once at app creation time (NOT per-request)
const invoiceRouteFactory    = require('./routes/invoices');
const withdrawalRouteFactory = require('./routes/withdrawals');

const logger = createLogger('api-server');
const app = express();

// ─── Trust proxy (for IP behind Nginx/load balancer) ─────────
// SECURITY: Only trust the first hop (Nginx). Never trust
// x-forwarded-for from clients directly.
app.set('trust proxy', 1);

// ═══════════════════════════════════════════════════════════════
// 1. SECURITY HEADERS (Helmet)
// ═══════════════════════════════════════════════════════════════
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      // UI-1: Remove 'unsafe-inline' — it allows CSS-based data exfiltration attacks
      // Use a nonce-based approach instead when inline styles are needed
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: config.env === 'production' ? [] : null,
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  crossOriginEmbedderPolicy: false,
  // UI-2: Permissions-Policy — disable dangerous browser APIs not needed for a payment API
  permissionsPolicy: {
    features: {
      geolocation: [],
      camera: [],
      microphone: [],
      payment: [],      // Disable browser Payment API to force use of our own flow
      usb: [],
      accelerometer: [],
      gyroscope: [],
      magnetometer: [],
    },
  },
}));

// UI-3: Expect-CT — enforce Certificate Transparency (detect rogue TLS certs)
app.use((req, res, next) => {
  res.setHeader('Expect-CT', `enforce, max-age=86400`);
  next();
});

// ═══════════════════════════════════════════════════════════════
// 2. CORS
// ═══════════════════════════════════════════════════════════════
app.use(cors({
  origin: config.env === 'production'
    ? (process.env.ALLOWED_ORIGINS || '').split(',').map((o) => o.trim()).filter(Boolean)
    : ['http://localhost:3000', 'http://localhost:5173', 'http://127.0.0.1:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: [
    'Content-Type', 'Authorization',
    'x-api-key', 'x-nonce', 'x-timestamp', 'x-signature',
    'x-idempotency-key', 'x-request-id',
  ],
  maxAge: 86400,
}));

// ═══════════════════════════════════════════════════════════════
// 3. RATE LIMITING
// ═══════════════════════════════════════════════════════════════

// General limiter: all /api/ routes
const generalLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.max,
  standardHeaders: true,
  legacyHeaders: false,
  store: rateLimitStore, // H2: Redis store (falls back to in-memory)
  message: response.error('RATE_LIMITED', 'Too many requests. Please try again later.'),
});
app.use('/api/', generalLimiter);

// Auth-specific limiter: stricter limits (separate bucket from general)
// A5: Three SEPARATE limiters — exhausting refresh cannot consume login budget
const _makeAuthLimiter = (prefix, max) => rateLimit({
  windowMs: config.rateLimit.windowMs,
  max,
  standardHeaders: true,
  legacyHeaders: false,
  store: rateLimitStore,
  validate: { keyGeneratorIpFallback: false }, // We handle IP trust via 'trust proxy'
  // Skip in test env — auth rate limit logic is tested via dedicated tests,
  // not via full integration (which causes validation tests to exhaust the limit first)
  skip: () => process.env.NODE_ENV === 'test',
  keyGenerator: (req) => `${prefix}:${req.ip || 'unknown'}`, // H1: keyed by IP for unauthenticated routes
  message: response.error('RATE_LIMITED', 'Too many authentication attempts. Account may be locked temporarily.'),
});

const loginLimiter    = _makeAuthLimiter('login',    config.rateLimit.authMax);	   // 5/15min
const registerLimiter = _makeAuthLimiter('register', config.rateLimit.authMax);     // 5/15min
const refreshLimiter  = _makeAuthLimiter('refresh',  config.rateLimit.authMax * 3); // 15/15min (refresh is legitimate repeated use)

// H3: Health endpoint light rate limit — prevent fingerprinting/load
const healthLimiter = rateLimit({
  windowMs: 60000,   // 1 minute
  max: 120,          // 2/second burst
  standardHeaders: false,
  legacyHeaders: false,
  store: rateLimitStore,
  validate: { keyGeneratorIpFallback: false },
  keyGenerator: (req) => `health:${req.ip || 'unknown'}`,
  message: response.error('RATE_LIMITED', 'Too many health check requests.'),
});

// 3b. PRE-AUTH IP-LEVEL SLIDING WINDOW RATE LIMIT (Gap 1 fix)
// ═══════════════════════════════════════════════════════════
// Runs BEFORE HMAC auth, nonce check, and merchant DB lookup.
// Blocks volumetric brute-force before any business logic executes.
// Three separate buckets by route class (auth, merchant-api, general).
// NOTE: ipRateLimit uses app.locals.redis which is injected in createApp().
//   The middleware itself checks req.app.locals.redis and fails open if not ready.
//   This is safe: at startup, Redis is connected before the first request arrives.
app.use('/api/v1/auth',          ipAuthLimiter);      // 20/5min per IP — strictest
app.use('/api/v1/payments',      ipMerchantLimiter);  // 120/min per IP
app.use('/api/v1/withdrawals',   ipMerchantLimiter);  // 120/min per IP
app.use('/api/',                 ipGeneralLimiter);   // 300/min per IP (general fallback)

// ═══════════════════════════════════════════════════════════
// 4. BODY PARSER — Service-specific size limits (Gap 3 fix)
// ═══════════════════════════════════════════════════════════
// WHY PER-ROUTE LIMITS:
//   A blanket 100kb limit allows a 100kb invoice-create payload which is absurd.
//   Oversized payloads waste CPU (JSON.parse on huge strings) and can be used
//   to DoS the server or probe for JSON parser vulnerabilities.
//   Each endpoint now has a limit sized to its maximum legitimate payload.
//
//   Auth (login/register/2FA):  8KB  — credentials + TOTP token, nothing bigger
//   Invoice create:            16KB  — amount + metadata + callback URL
//   Withdrawal create:          4KB  — amount + address, nothing bigger
//   Admin ops (bulk):         256KB  — bulk imports, OFAC list updates
//   General fallback:          32KB  — catch-all for unlisted routes
//
// IMPORTANT: More specific paths MUST be declared before less specific ones.
// Express matches the FIRST matching app.use() path.
if (config.env === 'production') {
  app.use((req, res, next) => {
    if (req.protocol === 'http') {
      return res.redirect(301, `https://${req.headers.host}${req.url}`);
    }
    next();
  });
}

// HTTP-1: Reject HTTP Request Smuggling attempts
app.use((req, res, next) => {
  if (req.headers['transfer-encoding'] && req.headers['content-length']) {
    return res.status(400).json(
      response.error('BAD_REQUEST', 'Ambiguous request: cannot have both Content-Length and Transfer-Encoding'),
    );
  }
  next();
});

// ═══════════════════════════════════════════════════════════
// 5. CONTENT-TYPE ENFORCEMENT (global — covers /api/, /admin/, /support/)
// ═══════════════════════════════════════════════════════════
// All mutation requests MUST send Content-Type: application/json.
// Blocks multipart injection, form-encoded bypass, and raw-body attacks.
// Global: previously only /api/ was covered — /admin/ and /support/ mutations
// also receive JSON bodies and were missing this guard.
app.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    const contentType = req.get('content-type');
    if (!contentType || !contentType.includes('application/json')) {
      return res.status(HttpStatus.UNPROCESSABLE).json(
        response.error('UNSUPPORTED_MEDIA_TYPE', 'Content-Type must be application/json'),
      );
    }
  }
  next();
});

// Service-specific body-size limits (Gap 3 fix) — ORDER IS CRITICAL
// More-specific paths MUST be declared before less-specific (Express matches first).
app.use('/api/v1/auth',       express.json({ limit: '8kb' }));    // login/register/2FA
app.use('/api/v1/payments',   express.json({ limit: '16kb' }));   // invoice create + metadata
app.use('/api/v1/withdrawals',express.json({ limit: '4kb' }));    // withdrawal: amount + address only
app.use('/admin/bulk',        express.json({ limit: '256kb' }));  // bulk imports, OFAC list
app.use('/admin',             express.json({ limit: '32kb' }));   // admin ops
app.use('/api/',              express.json({ limit: '32kb' }));   // general fallback
app.use(express.urlencoded({ extended: false, limit: '8kb' }));



// ═══════════════════════════════════════════════════════════════
// 6. NOSQL + PROTOTYPE INJECTION PREVENTION (MUST be AFTER body parser)
// ═══════════════════════════════════════════════════════════════
app.use(noSqlSanitize);

// ═══════════════════════════════════════════════════════════════
// 6b. WAF REQUEST HARDENING (#8 mainnet requirement)
// ═══════════════════════════════════════════════════════════════
// Code-level WAF: path traversal, null bytes, scanner UAs, host injection.
// Defense-in-depth BEFORE Cloudflare/Nginx WAF layer.
app.use(requestHardening); // Global: scanner UAs blocked on ALL routes

// ═══════════════════════════════════════════════════════════════
// 6c. CSRF-2: ORIGIN VALIDATION (MUST be AFTER body parser)
// ═══════════════════════════════════════════════════════════════
// Server-side Origin check — independent of CORS.
// Prevents CSRF on state-mutation endpoints.
app.use(validateOrigin);

// ═══════════════════════════════════════════════════════════════
// 7. HTTP PARAMETER POLLUTION PREVENTION
// ═══════════════════════════════════════════════════════════════
app.use(hpp());

// ═══════════════════════════════════════════════════════════════
// 8. COOKIE PARSER
// ═══════════════════════════════════════════════════════════════
app.use(cookieParser());

// 8b. API VERSIONING HEADERS (Gap 5 fix)
// ═══════════════════════════════════════════════════════════
// Every /api/ response carries X-API-Version so clients can detect version.
// When a v2 route is rolled out, deprecated v1 endpoints gain a Deprecation
// header (RFC 8594) so clients see warnings before the endpoint is removed.
// No breaking change — purely additive response headers.
const API_VERSION = process.env.API_VERSION || 'v1';
app.use('/api/', (req, res, next) => {
  res.setHeader('X-API-Version', API_VERSION);
  // Example (activate when deprecating a specific endpoint):
  // if (req.path.startsWith('/v1/legacy/')) {
  //   res.setHeader('Deprecation', 'Sat, 01 Jan 2026 00:00:00 GMT');
  //   res.setHeader('Sunset', 'Sat, 01 Jul 2026 00:00:00 GMT');
  //   res.setHeader('Link', '</api/v2/resource>; rel="successor-version"');
  // }
  next();
});

// 8c. PAGINATION DEPTH GUARD — global (Gap 6 fix, extended)
// ═══════════════════════════════════════════════════════════
// WHY: page=99999&limit=100 forces MongoDB to skip ~10M documents.
// Original guard only covered /api/ — missing /admin/ and /support/ list endpoints
// (e.g. GET /admin/transactions?page=99999 or GET /support/transactions?page=99999).
// Fix: global guard (no path prefix) — applies to ALL routes.
const MAX_PAGE  = parseInt(process.env.PAGINATION_MAX_PAGE, 10)  || 1000;
const MAX_LIMIT = parseInt(process.env.PAGINATION_MAX_LIMIT, 10) || 200;

app.use((req, res, next) => {
  if (req.method !== 'GET') return next();
  const page  = parseInt(req.query.page, 10);
  const limit = parseInt(req.query.limit, 10);
  if (!Number.isNaN(page) && page > MAX_PAGE) {
    return res.status(400).json(
      response.error('INVALID_PAGINATION', `Page cannot exceed ${MAX_PAGE}`),
    );
  }
  if (!Number.isNaN(limit) && limit > MAX_LIMIT) {
    return res.status(400).json(
      response.error('INVALID_PAGINATION', `Limit cannot exceed ${MAX_LIMIT}`),
    );
  }
  next();
});


// ═══════════════════════════════════════════════════════════════
// 9. REQUEST ID INJECTION
// ═══════════════════════════════════════════════════════════════
// Generates unique request ID for every request.
// Echoed back in response header for client-side correlation.
// GAP 7: Validate client-supplied x-request-id is a valid UUID.
// Reject arbitrary strings that could inject noise/attacks into logs.
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
app.use((req, res, next) => {
  const clientId = req.headers['x-request-id'];
  req.requestId = (clientId && UUID_REGEX.test(clientId)) ? clientId : randomUUID();
  res.setHeader('x-request-id', req.requestId);
  next();
});

// ═══════════════════════════════════════════════════════════════
// 10. REQUEST CONTEXT PROPAGATION (AsyncLocalStorage)
// ═══════════════════════════════════════════════════════════════
// MUST be AFTER requestId injection.
// Propagates requestId, ip, etc. through the entire call chain
// without manual parameter passing.
app.use(requestContextMiddleware);

// ═══════════════════════════════════════════════════════════════
// 11. REQUEST LOGGING
// ═══════════════════════════════════════════════════════════════
app.use((req, res, next) => {
  const start = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - start;
    const level = res.statusCode >= 400 ? 'warn' : 'info';

    logger[level]('HTTP', {
      requestId: req.requestId,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      ms: duration,
      ip: req.ip,
    });
  });

  next();
});

// ═══════════════════════════════════════════════════════════════
// 12. ROUTES
// ═══════════════════════════════════════════════════════════════

// A5: Each auth endpoint has its OWN rate limit bucket
app.use('/api/v1/auth/login',    loginLimiter);
app.use('/api/v1/auth/register', registerLimiter);
app.use('/api/v1/auth/refresh',  refreshLimiter);

// Route mounting
app.use('/api/v1/auth',             authRoutes);
app.use('/internal/health',         healthLimiter, healthRoutes);

// ─── Public routes (no auth) ──────────────────────────────────────────────────
// Public payment page — MUST be before any auth middleware
app.use('/api/v1/pay',              publicPayRoutes);

// ─── Merchant Portal (JWT-authenticated merchant self-service) ────────────────
app.use('/api/v1/merchant',         merchantPortalRoutes);

// ─── Admin routes (authenticate + authorize('admin') + IP whitelist inside) ───
app.use('/admin/wallets',           walletRoutes);
app.use('/admin/merchants',         merchantRoutes);
app.use('/admin/users',             adminUsersRoutes);
app.use('/admin/system',            adminSystemRoutes);
app.use('/admin/webhooks',          adminWebhooksRoutes);
app.use('/admin/reconciliation',    adminReconRoutes);
app.use('/admin',                   adminRoutes);   // dashboard, transactions, withdrawals, audit, disputes, fraud

// ─── Support routes (authenticate + authorize('support') + IP whitelist) ─────
app.use('/support',                 supportRoutes);

// ─── Merchant API (HMAC-signed) ── routers built ONCE at startup with Redis injected ──
// SECURITY: redisClient (hmacNonceRedis) is injected here for atomic nonce deduplication.
// In production: Redis SET NX (atomic). In dev without Redis: MongoDB UsedNonce (fallback).
// Routers are built at module load time — NOT per-request — to avoid recreating middleware.
app.use('/api/v1/payments',    invoiceRouteFactory(hmacNonceRedis));
app.use('/api/v1/withdrawals', withdrawalRouteFactory(hmacNonceRedis));

// ═══════════════════════════════════════════════════════════════
// 13. 404 HANDLER
// ═══════════════════════════════════════════════════════════════
// C4: Do NOT echo method/path — reveals API surface to attackers
app.use((req, res) => {
  res.status(HttpStatus.NOT_FOUND).json(
    response.error('NOT_FOUND', 'The requested resource was not found'),
  );
});

// ═══════════════════════════════════════════════════════════════
// 14. GLOBAL ERROR HANDLER
// ═══════════════════════════════════════════════════════════════
// Must have 4 params to be recognized as error middleware by Express.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  // Body parse failure (malformed JSON)
  if (err.type === 'entity.parse.failed') {
    return res.status(HttpStatus.BAD_REQUEST).json(
      response.error('INVALID_JSON', 'Request body contains invalid JSON'),
    );
  }

  // Payload too large
  if (err.type === 'entity.too.large') {
    return res.status(413).json(
      response.error('PAYLOAD_TOO_LARGE', 'Request body exceeds the maximum size limit'),
    );
  }

  // Circuit breaker open (dependency degraded) — Gap 6
  // When MongoDB or TronGrid is unhealthy, circuit breakers throw CircuitOpenError.
  // Return 503 + Retry-After so the load balancer routes away and clients back off.
  if (err.isCircuitOpen) {
    res.setHeader('Retry-After', String(err.retryInSec || 30));
    return res.status(503).json(
      response.error('SERVICE_UNAVAILABLE', 'A backend dependency is temporarily unavailable. Please retry.'),
    );
  }

  // Operational errors (expected, client mistakes)
  if (err instanceof AppError) {
    logger.warn('Operational error', {
      requestId: req.requestId,
      code: err.code,
      message: err.message,
      statusCode: err.statusCode,
    });
    // ID-2: Return generic code externally; detailed code in logs only
    const safeJson = err.toJSON();
    if (config.env === 'production' && safeJson.code && safeJson.code.includes('AUTH_')) {
      safeJson.code = 'AUTH_ERROR'; // Don't expose auth state machine to attackers
    }
    return res.status(err.statusCode).json(safeJson);
  }

  // Unexpected errors (bugs, system failures)
  logger.error('Unhandled error', {
    requestId: req.requestId,
    error: err.message,
    stack: config.env !== 'production' ? err.stack : '[hidden in production]',
  });

  return res.status(HttpStatus.INTERNAL_ERROR).json(
    response.error(
      'INTERNAL_ERROR',
      config.env === 'production' ? 'An unexpected error occurred' : err.message,
    ),
  );
});

/**
 * Factory function — creates the Express app with a Redis client injected.
 * Invoice and withdrawal routes need Redis for nonce deduplication.
 * Routers are built ONCE here, not on every request.
 *
 * @param {object} [redisClient]                  - IORedis instance
 * @param {object} [paymentCreatedPublisher]       - Queue publisher for payment.created events
 * @param {object} [withdrawalEligiblePublisher]   - Queue publisher for withdrawal.eligible events
 * @returns {express.Application}
 */
function createApp(redisClient, paymentCreatedPublisher, withdrawalEligiblePublisher) {
  if (redisClient) {
    app.locals.redis = redisClient;

    // IP Blocklist middleware — runs BEFORE all route handlers
    // Checks IpBlocklist model with Redis cache (1-min TTL)
    const checkIpBlock = require('./middleware/checkIpBlock');
    app.use('/api/', checkIpBlock({ redis: redisClient, logger }));
    app.use('/admin/', checkIpBlock({ redis: redisClient, logger }));

    const invoiceRouter    = invoiceRouteFactory(redisClient);
    const withdrawalRouter = withdrawalRouteFactory(redisClient);
    app.locals._invoiceRouter    = invoiceRouter;
    app.locals._withdrawalRouter = withdrawalRouter;
  }

  if (paymentCreatedPublisher) {
    const { setPaymentCreatedPublisher } = require('./controllers/invoiceController');
    setPaymentCreatedPublisher(paymentCreatedPublisher);
  }

  // Wire withdrawal.eligible publisher — enables manual withdrawal requests to
  // be picked up by the withdrawal engine for signing
  if (withdrawalEligiblePublisher) {
    const { setWithdrawalEligiblePublisher } = require('./controllers/withdrawalController');
    setWithdrawalEligiblePublisher(withdrawalEligiblePublisher);
    // Admin controller also needs it for approved high-value withdrawals
    const { setWithdrawalEligiblePublisher: setAdminWdlPub } = require('./controllers/adminController');
    setAdminWdlPub(withdrawalEligiblePublisher);
  }

  return app;
}

module.exports = { app, createApp };
