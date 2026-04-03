'use strict';

/**
 * @module middleware/confirmCriticalAction
 *
 * Critical Action Re-confirmation Middleware.
 *
 * Banking-grade: High-risk admin operations (approve large withdrawals,
 * emergency pause, user role changes) require the admin to provide their
 * current TOTP code AS PART OF THE SAME REQUEST.
 *
 * This prevents:
 *   - CSRF: Even a valid session cannot trigger critical actions without TOTP
 *   - Session hijacking: Stolen JWT token alone is not enough
 *   - Compromised admin PC: Attacker needs the physical TOTP device
 *
 * REQUEST FORMAT:
 *   The request body must include: { _totpCode: "123456" }
 *   (Uses underscore prefix to distinguish from domain data)
 *
 * Usage:
 *   router.put('/withdrawals/:id/approve',
 *     authenticate, authorize('admin'), adminIpWhitelist(),
 *     confirmCriticalAction,
 *     approveWithdrawal
 *   );
 */

const speakeasy  = require('speakeasy');
const { User }   = require('@xcg/database');
const { AppError }  = require('@xcg/common');
const { createLogger }= require('@xcg/logger');

const logger = createLogger('security');

async function confirmCriticalAction(req, res, next) {
  try {
    const { _totpCode } = req.body;

    if (!_totpCode) {
      return next(AppError.badRequest(
        'Critical action requires TOTP re-confirmation. Include _totpCode in request body.',
      ));
    }

    // Validate format: 6 digits
    if (!/^\d{6}$/.test(String(_totpCode))) {
      return next(AppError.badRequest('Invalid TOTP code format — must be 6 digits'));
    }

    // Get user's TOTP secret from DB
    const user = await User.findById(req.user.userId)
      .select('twoFactorSecret twoFactorEnabled')
      .lean();

    if (!user?.twoFactorEnabled || !user?.twoFactorSecret) {
      return next(AppError.forbidden(
        'Critical action requires 2FA. Enable 2FA first at /api/v1/auth/2fa/setup',
      ));
    }

    // Verify TOTP — window ±1 period (30s) to account for clock skew
    const isValid = speakeasy.totp.verify({
      secret:   user.twoFactorSecret,
      encoding: 'base32',
      token:    String(_totpCode),
      window:   1,
    });

    if (!isValid) {
      logger.warn('Critical action TOTP rejected', {
        userId: req.user.userId,
        role:   req.user.role,
        ip:     req.ip,
        path:   req.path,
      });
      return next(AppError.unauthorized('Invalid TOTP code — critical action denied'));
    }

    // Remove _totpCode from body so it doesn't get processed as domain data
    delete req.body._totpCode;

    next();
  } catch (err) {
    next(err);
  }
}

module.exports = { confirmCriticalAction };
