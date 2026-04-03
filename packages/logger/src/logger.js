'use strict';

/**
 * Structured JSON Logger.
 *
 * Every log entry is a JSON object with:
 *   timestamp, level, service, message, and contextual data.
 *
 * Log levels: error, warn, info, debug
 *
 * Security rules:
 *   - NEVER log private keys, passwords, or secrets
 *   - NEVER log full request bodies containing sensitive data
 *   - Sanitize user input before logging
 *   - Production: only warn + error to console, info to file
 */

const LOG_LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };

/**
 * Fields that must NEVER appear in logs.
 * If these keys are found in log data, they are redacted.
 */
const SENSITIVE_FIELDS = new Set([
  'password', 'newpassword', 'currentpassword', 'confirmpassword',
  'privatekey', 'encryptedprivatekey', 'masterkey',
  'secret', 'apisecret', 'webhooksecret',
  'token', 'accesstoken', 'refreshtoken',
  'authorization', 'cookie',
  'totpsecret', 'totpcode',
  'twofactorsecret', 'passwordhash', 'passwordhistory',
  'keyhash', 'tokenhash', 'salt',
]);

/**
 * Recursively redact sensitive fields from an object.
 *
 * @param {object} obj - Object to sanitize
 * @param {number} [depth=0] - Current recursion depth
 * @returns {object} Sanitized copy (original not modified)
 */
function sanitize(obj, depth = 0) {
  if (depth > 5 || obj === null || obj === undefined) return obj;
  if (typeof obj !== 'object') return obj;
  if (obj instanceof Error) {
    return {
      name: obj.name,
      message: obj.message,
      code: obj.code,
      statusCode: obj.statusCode,
      // Stack traces only in non-production
      ...(process.env.NODE_ENV !== 'production' && { stack: obj.stack }),
    };
  }

  const sanitized = Array.isArray(obj) ? [] : {};
  for (const [key, value] of Object.entries(obj)) {
    if (SENSITIVE_FIELDS.has(key.toLowerCase())) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitize(value, depth + 1);
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

/**
 * Create a logger instance for a specific service.
 *
 * @param {string} serviceName - Name of the service (e.g., 'api-server', 'matching-engine')
 * @returns {object} Logger with error, warn, info, debug methods
 */
function createLogger(serviceName) {
  const minLevel = process.env.NODE_ENV === 'production' ? 'warn' : 'debug';
  const minLevelNum = LOG_LEVELS[minLevel] ?? LOG_LEVELS.debug;

  /**
   * Core log function.
   *
   * @param {string} level - Log level
   * @param {string} message - Log message
   * @param {object} [data={}] - Additional contextual data
   */
  function log(level, message, data = {}) {
    if (LOG_LEVELS[level] > minLevelNum) return;

    const entry = {
      timestamp: new Date().toISOString(),
      level,
      service: serviceName,
      message,
      ...sanitize(data),
    };

    const output = JSON.stringify(entry);

    if (level === 'error') {
      process.stderr.write(output + '\n');
    } else {
      process.stdout.write(output + '\n');
    }
  }

  return {
    error: (message, data) => log('error', message, data),
    warn: (message, data) => log('warn', message, data),
    info: (message, data) => log('info', message, data),
    debug: (message, data) => log('debug', message, data),

    /**
     * Create a child logger with default context fields.
     * Useful for adding requestId, userId, etc. to all logs in a request.
     *
     * @param {object} context - Default fields to include in every log
     * @returns {object} Child logger
     */
    child: (context) => {
      const childLogger = createLogger(serviceName);
      const originalMethods = { ...childLogger };

      ['error', 'warn', 'info', 'debug'].forEach((lvl) => {
        childLogger[lvl] = (msg, data = {}) => {
          originalMethods[lvl](msg, { ...context, ...data });
        };
      });

      return childLogger;
    },
  };
}

module.exports = { createLogger, sanitize, SENSITIVE_FIELDS };
