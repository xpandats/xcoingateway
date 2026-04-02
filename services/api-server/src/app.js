'use strict';

/**
 * Express Application Setup.
 *
 * Security middleware applied BEFORE any routes:
 *   1. Helmet (security headers)
 *   2. CORS (strict origin whitelist)
 *   3. Rate limiting
 *   4. Body parser with size limit
 *   5. Cookie parser (for refresh tokens)
 *   6. Request ID injection
 *   7. Request logging
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
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
  crossOriginEmbedderPolicy: false, // Allow API responses
}));

// ─── 2. CORS ──────────────────────────────────────────────────
app.use(cors({
  origin: config.env === 'production'
    ? [] // Add production domains here
    : ['http://localhost:3000', 'http://localhost:5173', 'http://127.0.0.1:3000'],
  credentials: true, // For refresh token cookies
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key', 'x-nonce', 'x-timestamp', 'x-signature', 'x-idempotency-key'],
  maxAge: 86400, // Cache preflight for 24h
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

// Stricter rate limit for auth endpoints
const authLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.authMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { code: 'RATE_LIMITED', message: 'Too many authentication attempts' } },
});

// ─── 4. Body Parser (with size limit) ────────────────────────
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

// ─── 5. Cookie Parser ────────────────────────────────────────
app.use(cookieParser());

// ─── 6. Request ID Injection ─────────────────────────────────
app.use((req, res, next) => {
  req.requestId = req.headers['x-request-id'] || randomUUID();
  res.setHeader('x-request-id', req.requestId);
  next();
});

// ─── 7. Request Logging ──────────────────────────────────────
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
app.use('/api/v1/auth', authLimiter, authRoutes);
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
  // Handle known operational errors
  if (err instanceof AppError) {
    logger.warn('Operational error', {
      requestId: req.requestId,
      code: err.code,
      message: err.message,
      statusCode: err.statusCode,
    });
    return res.status(err.statusCode).json(err.toJSON());
  }

  // Handle unexpected errors
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
