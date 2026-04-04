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
const { randomUUID } = require('@xcg/crypto');
const { createLogger } = require('@xcg/logger');
const { AppError, HttpStatus, response, requestContextMiddleware } = require('@xcg/common');
const { config } = require('./config');
const { validateOrigin } = require('./middleware/originValidation');

// H2: Attempt to use Redis store for rate limiting (survives restarts, works across instances)
// Falls back to in-memory store if Redis is unavailable (safe for single-instance dev)
let rateLimitStore;
try {
  const RedisStore = require('rate-limit-redis');
  const { createClient } = require('redis');
  const redisClient = createClient({ url: config.redis.url });
  redisClient.connect().catch(() => {}); // Non-blocking connect
  rateLimitStore = new RedisStore({ sendCommand: (...args) => redisClient.sendCommand(args) });
} catch {
  // rate-limit-redis not installed or Redis unavailable — use in-memory (dev only)
  rateLimitStore = undefined;
}



// ─── Route Imports ───────────────────────────────────────────────────────────
const authRoutes         = require('./routes/auth');
const healthRoutes       = require('./routes/health');
const walletRoutes       = require('./routes/wallets');
const merchantRoutes     = require('./routes/merchants');
const adminRoutes        = require('./routes/admin');
const supportRoutes      = require('./routes/support');
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
  keyGenerator: (req) => `${prefix}:${req.ip}`, // H1: keyed by IP for unauthenticated routes
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
  message: response.error('RATE_LIMITED', 'Too many health check requests.'),
});

// ═══════════════════════════════════════════════════════════════
// 4. BODY PARSER (strict size limits)
// ═══════════════════════════════════════════════════════════════
// HTTP-2: Force HTTPS in production (for users before HSTS is cached)
if (config.env === 'production') {
  app.use((req, res, next) => {
    if (req.protocol === 'http') {
      return res.redirect(301, `https://${req.headers.host}${req.url}`);
    }
    next();
  });
}

// HTTP-1: Reject HTTP Request Smuggling attempts
// Requests with BOTH Content-Length and Transfer-Encoding are ambiguous
// and exploited for request smuggling attacks
app.use((req, res, next) => {
  if (req.headers['transfer-encoding'] && req.headers['content-length']) {
    return res.status(400).json(
      response.error('BAD_REQUEST', 'Ambiguous request: cannot have both Content-Length and Transfer-Encoding'),
    );
  }
  next();
});

// Auth routes: 10KB (login/register payloads are tiny)
// All other API routes: 100KB
app.use('/api/v1/auth', express.json({ limit: '10kb' }));
app.use('/api/', express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// ═══════════════════════════════════════════════════════════════
// 5. CONTENT-TYPE ENFORCEMENT
// ═══════════════════════════════════════════════════════════════
// All mutation requests MUST be application/json.
// Blocks multipart attacks and form-encoded injection vectors.
app.use('/api/', (req, res, next) => {
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

// ═══════════════════════════════════════════════════════════════
// 6. NOSQL + PROTOTYPE INJECTION PREVENTION (MUST be AFTER body parser)
// ═══════════════════════════════════════════════════════════════
app.use(noSqlSanitize);

// ═══════════════════════════════════════════════════════════════
// 6b. CSRF-2: ORIGIN VALIDATION (MUST be AFTER body parser)
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

// ═══════════════════════════════════════════════════════════════
// 9. REQUEST ID INJECTION
// ═══════════════════════════════════════════════════════════════
// Generates unique request ID for every request.
// Echoed back in response header for client-side correlation.
app.use((req, res, next) => {
  req.requestId = req.headers['x-request-id'] || randomUUID();
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

// ─── Admin routes (authenticate + authorize('admin') + IP whitelist inside) ───
app.use('/admin/wallets',           walletRoutes);
app.use('/admin/merchants',         merchantRoutes);
app.use('/admin',                   adminRoutes);   // dashboard, transactions, withdrawals, audit

// ─── Support routes (authenticate + authorize('support') + IP whitelist) ─────
app.use('/support',                 supportRoutes);

// ─── Merchant API (HMAC-signed) ── routers built once in createApp() ───────────────
// Delegate to cached pre-built routers (avoids per-request router creation)
app.use('/api/v1/payments',    (req, res, next) => (req.app.locals._invoiceRouter    || invoiceRouteFactory(null))(req, res, next));
app.use('/api/v1/withdrawals', (req, res, next) => (req.app.locals._withdrawalRouter || withdrawalRouteFactory(null))(req, res, next));

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
 * @param {object} [redisClient]            - IORedis instance
 * @param {object} [paymentCreatedPublisher] - Queue publisher for payment.created events
 * @returns {express.Application}
 */
function createApp(redisClient, paymentCreatedPublisher) {
  if (redisClient) {
    app.locals.redis = redisClient;
    // Build routers ONCE at startup with the real Redis client
    // This prevents the per-request router creation memory leak
    const invoiceRouter    = invoiceRouteFactory(redisClient);
    const withdrawalRouter = withdrawalRouteFactory(redisClient);

    // Remove previous per-request middleware and replace with static routers
    // Using a fresh router cache stored in app.locals
    app.locals._invoiceRouter    = invoiceRouter;
    app.locals._withdrawalRouter = withdrawalRouter;
  }

  // Wire payment.created publisher into invoice controller (non-blocking event)
  if (paymentCreatedPublisher) {
    const { setPaymentCreatedPublisher } = require('./controllers/invoiceController');
    setPaymentCreatedPublisher(paymentCreatedPublisher);
  }

  return app;
}

module.exports = { app, createApp };
