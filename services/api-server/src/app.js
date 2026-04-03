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

const authRoutes = require('./routes/auth');
const healthRoutes = require('./routes/health');

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
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  crossOriginEmbedderPolicy: false,
}));

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
  message: response.error('RATE_LIMITED', 'Too many requests. Please try again later.'),
});
app.use('/api/', generalLimiter);

// Auth-specific limiter: stricter limits on auth endpoints
const authLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.authMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: response.error('RATE_LIMITED', 'Too many authentication attempts. Account may be locked temporarily.'),
});

// ═══════════════════════════════════════════════════════════════
// 4. BODY PARSER (strict size limits)
// ═══════════════════════════════════════════════════════════════
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
// 6. NOSQL INJECTION PREVENTION (MUST be AFTER body parser)
// ═══════════════════════════════════════════════════════════════
app.use(noSqlSanitize);

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

// Auth limiter on sensitive public endpoints
app.use('/api/v1/auth/login', authLimiter);
app.use('/api/v1/auth/register', authLimiter);
app.use('/api/v1/auth/refresh', authLimiter);

// Route mounting
app.use('/api/v1/auth', authRoutes);
app.use('/internal/health', healthRoutes);

// ═══════════════════════════════════════════════════════════════
// 13. 404 HANDLER
// ═══════════════════════════════════════════════════════════════
app.use((req, res) => {
  res.status(HttpStatus.NOT_FOUND).json(
    response.error('NOT_FOUND', `Route ${req.method} ${req.path} not found`),
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
    return res.status(err.statusCode).json(err.toJSON());
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

module.exports = app;
