'use strict';

/**
 * @module utils/safeFilePath
 *
 * INJ-4: Path Traversal Prevention Utility.
 *
 * ATTACK: req.params.filename = "../../etc/passwd"
 * Without validation, fs.readFile(path.join(base, filename)) reads system files.
 *
 * This utility must be used for ANY operation that:
 *   - Reads files based on user input
 *   - Writes files to user-specified locations
 *   - Generates file paths from user data
 *
 * USAGE:
 *   const safe = safeFilePath('/app/uploads', req.params.filename);
 *   // safe is guaranteed to be inside /app/uploads or throws
 */

const path = require('path');

/**
 * Resolve a user-provided filename safely within an allowed base directory.
 *
 * @param {string} allowedBase - Absolute path to the allowed directory
 * @param {string} userInput - User-provided filename or relative path
 * @returns {string} Absolute safe path
 * @throws {Error} If the resolved path escapes the allowed directory
 */
function safeFilePath(allowedBase, userInput) {
  if (!allowedBase || typeof allowedBase !== 'string') {
    throw new Error('safeFilePath: allowedBase must be a non-empty string');
  }
  if (!userInput || typeof userInput !== 'string') {
    throw new Error('safeFilePath: userInput must be a non-empty string');
  }

  // Strip any null bytes (classic NUL byte injection trick)
  const sanitized = userInput.replace(/\0/g, '');

  // Resolve to absolute path
  const resolvedBase = path.resolve(allowedBase);
  const resolvedTarget = path.resolve(resolvedBase, sanitized);

  // The resolved path MUST start with the resolved base
  if (!resolvedTarget.startsWith(resolvedBase + path.sep) &&
      resolvedTarget !== resolvedBase) {
    throw new Error(
      `Path traversal detected: "${userInput}" resolves outside allowed directory`,
    );
  }

  return resolvedTarget;
}

module.exports = { safeFilePath };
