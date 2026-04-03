'use strict';

/**
 * @module @xcg/common/requestContext
 *
 * Request Context Propagation via AsyncLocalStorage.
 *
 * WHY: In a bank-grade system, every log entry, every audit record,
 * every error must be traceable back to the exact HTTP request that
 * triggered it. Passing `requestId` manually through every function
 * call is error-prone and pollutes signatures.
 *
 * AsyncLocalStorage provides automatic context propagation across
 * the entire async call chain without explicit parameter passing.
 *
 * USAGE:
 *   // In middleware (once, at top of stack):
 *   app.use(requestContextMiddleware);
 *
 *   // Anywhere in the call chain:
 *   const { getRequestContext } = require('@xcg/common');
 *   const ctx = getRequestContext();
 *   console.log(ctx.requestId); // Always available
 */

const { AsyncLocalStorage } = require('async_hooks');

const asyncLocalStorage = new AsyncLocalStorage();

/**
 * Get the current request context.
 * Returns empty object if called outside a request context.
 *
 * @returns {{ requestId?: string, userId?: string, role?: string, ip?: string }}
 */
function getRequestContext() {
  return asyncLocalStorage.getStore() || {};
}

/**
 * Run a function within a request context.
 * Used internally by the middleware, but also available for
 * background jobs that need their own context.
 *
 * @param {object} context - Context fields to propagate
 * @param {Function} fn - Function to run within context
 * @returns {*} Return value of fn
 */
function runWithContext(context, fn) {
  return asyncLocalStorage.run(context, fn);
}

/**
 * Express middleware: creates request context for the entire request lifecycle.
 * Must be mounted AFTER requestId injection middleware.
 */
function requestContextMiddleware(req, _res, next) {
  const context = {
    requestId: req.requestId || 'unknown',
    ip: req.ip,
    method: req.method,
    path: req.path,
    userAgent: req.get('user-agent') || 'unknown',
    // userId and role are set by authenticate middleware later
  };

  asyncLocalStorage.run(context, () => {
    next();
  });
}

/**
 * Update the current request context (e.g., after authentication).
 * Used by authenticate middleware to add userId and role.
 *
 * @param {object} fields - Fields to merge into context
 */
function updateRequestContext(fields) {
  const store = asyncLocalStorage.getStore();
  if (store) {
    Object.assign(store, fields);
  }
}

module.exports = {
  getRequestContext,
  runWithContext,
  requestContextMiddleware,
  updateRequestContext,
};
