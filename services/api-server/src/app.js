'use strict';

/**
 * Express Application — Security-Hardened.
 *
 * Middleware stack (applied in strict order):
 *   1. Helmet (security headers)
 *   2. CORS (strict origin whitelist)
 *   3. Rate limiting (general + auth-specific)
 *   4. Body parser (strict size limits)
 *   5. Content-Type enforcement
 *   6. NoSQL Injection prevention (MUST be after body parser)
 *   7. HPP (HTTP Parameter Pollution)
 *   8. Cookie parser
 *   9. Request ID injection
 *   10. Request logging
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { noSqlSanitize } = require('./middleware/noSqlSanitize');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const { randomUUID } = require('@xcg/crypto');
const { createLogger } = require('@xcg/logger');
const { AppError, HttpStatus } = require('@xcg/common');
const { config } = require('./config');

const authRoutes = require('./routes/auth');
const healthRoutes = require('./routes/health');

const logger = createLogger('api-server');
const app = express();

// ─── Trust proxy (for rate limiting behind Nginx) ─────────────
app.set('trust proxy', 1);

// ─── 1. Security Headers ─────────────────────────────────────
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

// ─── 2. CORS ──────────────────────────────────────────────────
app.use(cors({
  origin: config.env === 'production'
    ? [] // Add production domains here
    : ['http://localhost:3000', 'http://localhost:5173', 'http://127.0.0.1:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key', 'x-nonce', 'x-timestamp', 'x-signature', 'x-idempotency-key', 'x-request-id'],
  maxAge: 86400,
}));

// ─── 3. Rate Limiting ────────────────────────────────────────
const generalLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.max,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { code: 'RATE_LIMITED', message: 'Too many requests, please try again later' } },
});
app.use('/api/', generalLimiter);

const authLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.authMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { code: 'RATE_LIMITED', message: 'Too many authentication attempts' } },
});

// ─── 4. Body Parser (strict size limits) ─────────────────────
app.use('/api/v1/auth', express.json({ limit: '10kb' }));
app.use('/api/', express.json({ limit: '100kb' }));
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// ─── 5. Content-Type Enforcement ─────────────────────────────
app.use('/api/', (req, res, next) => {
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    const contentType = req.get('content-type');
    if (!contentType || !contentType.includes('application/json')) {
      return res.status(415).json({
        error: {
          code: 'UNSUPPORTED_MEDIA_TYPE',
          message: 'Content-Type must be application/json',
        },
      });
    }
  }
  next();
});

// ─── 6. NoSQL Injection Prevention (AFTER body parser) ───────
// Custom middleware: strips MongoDB operators ($gt, $ne, $where, etc.)
// from req.body, req.query, and req.params.
app.use(noSqlSanitize);

// ─── 7. HTTP Parameter Pollution Prevention ──────────────────
app.use(hpp());

// ─── 8. Cookie Parser ────────────────────────────────────────
app.use(cookieParser());

// ─── 9. Request ID Injection ─────────────────────────────────
app.use((req, res, next) => {
  req.requestId = req.headers['x-request-id'] || randomUUID();
  res.setHeader('x-request-id', req.requestId);
  next();
});

// ─── 10. Request Logging ─────────────────────────────────────
app.use((req, res, next) => {
  const start = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - start;
    const level = res.statusCode >= 400 ? 'warn' : 'info';

    logger[level]('HTTP Request', {
      requestId: req.requestId,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration_ms: duration,
      ip: req.ip,
      userAgent: req.get('user-agent'),
    });
  });

  next();
});

// ─── Routes ──────────────────────────────────────────────────
app.use('/api/v1/auth/login', authLimiter);
app.use('/api/v1/auth/register', authLimiter);
app.use('/api/v1/auth/refresh', authLimiter);
app.use('/api/v1/auth', authRoutes);
app.use('/internal/health', healthRoutes);

// ─── 404 Handler ─────────────────────────────────────────────
app.use((req, res) => {
  res.status(HttpStatus.NOT_FOUND).json({
    error: {
      code: 'NOT_FOUND',
      message: `Route ${req.method} ${req.path} not found`,
    },
  });
});

// ─── Global Error Handler ────────────────────────────────────
app.use((err, req, res, _next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({
      error: { code: 'INVALID_JSON', message: 'Request body contains invalid JSON' },
    });
  }

  if (err.type === 'entity.too.large') {
    return res.status(413).json({
      error: { code: 'PAYLOAD_TOO_LARGE', message: 'Request body exceeds size limit' },
    });
  }

  if (err instanceof AppError) {
    logger.warn('Operational error', {
      requestId: req.requestId,
      code: err.code,
      message: err.message,
      statusCode: err.statusCode,
    });
    return res.status(err.statusCode).json(err.toJSON());
  }

  logger.error('Unhandled error', {
    requestId: req.requestId,
    error: err.message,
    stack: config.env !== 'production' ? err.stack : undefined,
  });

  return res.status(HttpStatus.INTERNAL_ERROR).json({
    error: {
      code: 'INTERNAL_ERROR',
      message: config.env === 'production'
        ? 'An unexpected error occurred'
        : err.message,
    },
  });
});

module.exports = app;
