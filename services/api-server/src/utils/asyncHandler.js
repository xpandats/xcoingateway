'use strict';

/**
 * @module utils/asyncHandler
 *
 * Wraps async route handlers to properly pass errors to Express.
 * Without this, async errors are unhandled rejections.
 *
 * USAGE: router.get('/', asyncHandler(async (req, res) => { ... }))
 */

function asyncHandler(fn) {
  return function (req, res, next) {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

module.exports = asyncHandler;
