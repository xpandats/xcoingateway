'use strict';

/**
 * @module middleware/require2FA
 *
 * Enforce 2FA for admin and super_admin roles.
 *
 * Banking-grade: High-privilege accounts (admin, super_admin) MUST have 2FA enabled.
 * If ADMIN_2FA_REQUIRED=true in config, any admin login without 2FA is blocked
 * at the middleware level before any route handler executes.
 *
 * This runs AFTER authenticate() (user is already verified).
 *
 * Attack vector prevented:
 *   - Admin credential compromise without physical access to TOTP device
 *   - Credential stuffing attacks against admin accounts
 */

const { AppError } = require('@xcg/common');
const { ROLES }    = require('@xcg/common').constants;
const { User }     = require('@xcg/database');
const { config }   = require('../config');
const { createLogger } = require('@xcg/logger');

const logger = createLogger('security');

const ADMIN_ROLES = new Set([ROLES.SUPER_ADMIN, ROLES.ADMIN]);

/**
 * Middleware: require 2FA to be enabled for admin/super_admin roles.
 * Must be placed AFTER authenticate().
 */
async function require2FA(req, res, next) {
  try {
    // Only enforce for admin roles
    if (!ADMIN_ROLES.has(req.user?.role)) {
      return next();
    }

    // Check if 2FA enforcement is enabled in config
    if (!config.admin.require2FA) {
      return next(); // Disabled in dev/staging — skip
    }

    // Fresh DB check — don't trust JWT claim for 2FA status
    const user = await User.findById(req.user.userId)
      .select('twoFactorEnabled role')
      .lean();

    if (!user) {
      return next(AppError.unauthorized('User not found'));
    }

    if (!user.twoFactorEnabled) {
      logger.warn('Admin access blocked — 2FA not enabled', {
        userId: req.user.userId,
        role:   req.user.role,
        ip:     req.ip,
        path:   req.path,
      });
      return next(AppError.forbidden(
        'Admin accounts must have 2FA enabled. Set up 2FA at /api/v1/auth/2fa/setup before accessing admin routes.',
      ));
    }

    next();
  } catch (err) {
    next(err);
  }
}

module.exports = { require2FA };
