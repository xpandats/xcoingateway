'use strict';

/**
 * @module @xcg/database/plugins/secureFields
 *
 * Mongoose plugin: Secure Field Exclusion — Defense in Depth.
 *
 * PROBLEM:
 *   `toSafeJSON()` only strips sensitive fields AFTER they are fetched
 *   from MongoDB. If a developer forgets to call `toSafeJSON()`, or uses
 *   `.lean()` (which returns plain objects without methods), all sensitive
 *   fields are exposed at the application layer.
 *
 * SOLUTION:
 *   This plugin registers a `pre('find')` and `pre('findOne')` hook that
 *   applies field exclusion at the QUERY LEVEL — MongoDB never sends
 *   `passwordHash`, `twoFactorSecret`, or `passwordHistory` to the app,
 *   regardless of whether `toSafeJSON()` is called.
 *
 * OVERRIDE:
 *   When a service NEEDS sensitive fields (e.g., authService for password
 *   comparison), it must explicitly select them:
 *     User.findById(id).select('+passwordHash')
 *   Fields excluded by default use the `+fieldName` opt-in convention.
 *
 * USAGE (applied automatically by database/index.js):
 *   userSchema.plugin(secureFieldsPlugin, {
 *     sensitiveFields: ['passwordHash', 'twoFactorSecret', 'passwordHistory'],
 *   });
 */

/**
 * @param {mongoose.Schema} schema
 * @param {{ sensitiveFields: string[] }} options
 */
function secureFieldsPlugin(schema, options) {
  const { sensitiveFields = [] } = options;
  if (sensitiveFields.length === 0) return;

  // Mark fields as 'select: false' — excluded by default, opt-in with '+'
  for (const field of sensitiveFields) {
    const pathConfig = schema.path(field);
    if (pathConfig) {
      pathConfig.options.select = false;
    }
  }
}

module.exports = { secureFieldsPlugin };
