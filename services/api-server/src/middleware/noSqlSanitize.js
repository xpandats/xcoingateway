'use strict';

/**
 * NoSQL Injection Prevention Middleware.
 *
 * Recursively removes MongoDB query operators ($gt, $ne, $where, etc.)
 * from request body, query, and params.
 *
 * Why custom instead of express-mongo-sanitize:
 *   - express-mongo-sanitize has compatibility issues with some Express versions
 *   - Custom implementation gives us full control and logging
 *   - Zero dependencies
 *
 * Attack vectors blocked:
 *   {"email": {"$gt": ""}}       → email becomes {}
 *   {"password": {"$ne": ""}}    → password becomes {}
 *   {"$where": "1==1"}           → key removed entirely
 */

const { createLogger } = require('@xcg/logger');
const logger = createLogger('security');

// Any key starting with $ is a MongoDB operator
const DOLLAR_KEY = /^\$/;

// INJ-2: Prototype pollution keys — equally dangerous as NoSQL injection
// {"__proto__":{"isAdmin":true}} poisons the entire Object prototype chain
const PROTOTYPE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const BANNED_KEY = (key) => DOLLAR_KEY.test(key) || PROTOTYPE_KEYS.has(key);

/**
 * Recursively sanitize an object by removing MongoDB operators.
 * @param {*} obj - Object to sanitize
 * @param {string} context - Path context for logging
 * @returns {{ sanitized: *, found: boolean }}
 */
function sanitize(obj, context = '') {
  if (obj === null || obj === undefined) return { sanitized: obj, found: false };
  if (typeof obj !== 'object') return { sanitized: obj, found: false };
  if (Array.isArray(obj)) {
    let found = false;
    const sanitized = obj.map((item, i) => {
      const result = sanitize(item, `${context}[${i}]`);
      if (result.found) found = true;
      return result.sanitized;
    });
    return { sanitized, found };
  }

  let found = false;
  const result = {};
  for (const key of Object.keys(obj)) {
    if (BANNED_KEY(key)) {
      found = true;
      // Skip this key entirely (don't copy it)
      continue;
    }
    const child = sanitize(obj[key], `${context}.${key}`);
    if (child.found) found = true;
    result[key] = child.sanitized;
  }

  return { sanitized: result, found };
}

/**
 * Express middleware: sanitize req.body, req.query, req.params
 */
function noSqlSanitize(req, res, next) {
  let injectionDetected = false;

  if (req.body && typeof req.body === 'object') {
    const result = sanitize(req.body, 'body');
    if (result.found) {
      injectionDetected = true;
      req.body = result.sanitized;
    }
  }

  if (req.query && typeof req.query === 'object') {
    const result = sanitize(req.query, 'query');
    if (result.found) {
      injectionDetected = true;
      req.query = result.sanitized;
    }
  }

  if (req.params && typeof req.params === 'object') {
    const result = sanitize(req.params, 'params');
    if (result.found) {
      injectionDetected = true;
      req.params = result.sanitized;
    }
  }

  if (injectionDetected) {
    logger.warn('NoSQL injection attempt blocked', {
      requestId: req.requestId || 'N/A',
      ip: req.ip,
      method: req.method,
      path: req.path,
    });
  }

  next();
}

module.exports = { noSqlSanitize, sanitize };
