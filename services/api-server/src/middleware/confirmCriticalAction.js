'use strict';

/**
 * @module middleware/confirmCriticalAction
 *
 * Critical Action Re-confirmation Middleware — Bank-Grade.
 *
 * Banking-grade: High-risk admin operations (approve large withdrawals,
 * emergency pause, user role changes) require the admin to provide their
 * current TOTP code AS PART OF THE SAME REQUEST.
 *
 * This prevents:
 *   - CSRF: Even a valid session cannot trigger critical actions without TOTP
 *   - Session hijacking: Stolen JWT token alone is not enough
 *   - Compromised admin PC: Attacker needs the physical TOTP device
 *   - TOTP REPLAY: Same 6-digit code cannot be submitted twice within its 90s validity window
 *
 * REQUEST FORMAT:
 *   The request body must include: { _totpCode: "123456" }
 *   (Uses underscore prefix to distinguish from domain data)
 *
 * TOTP REPLAY PREVENTION (Gap 1 fix):
 *   A valid TOTP code is valid for 90 seconds (window ±1 = 3 × 30s periods).
 *   Without replay prevention, the same code could approve MULTIPLE critical
 *   actions in that window (e.g., approve withdrawal → approve blacklist → etc.)
 *   even from a stolen code.
 *
 *   Fix: After successful verification, the code is recorded in UsedTotpCode
 *   (compound unique index on userId+code). If the same admin submits the same
 *   code again within the TTL window, the duplicate DB insert fails with a
 *   unique constraint violation → code rejected. TTL = 90s auto-deletes stale entries.
 *
 * Usage:
 *   router.put('/withdrawals/:id/approve',
 *     authenticate, authorize('admin'), adminIpWhitelist(),
 *     confirmCriticalAction,
 *     approveWithdrawal
 *   );
 */

const speakeasy        = require('speakeasy');
const { User, UsedTotpCode } = require('@xcg/database');
const { AppError }     = require('@xcg/common');
const { createLogger } = require('@xcg/logger');

const logger = createLogger('security');

async function confirmCriticalAction(req, res, next) {
  try {
    const { _totpCode } = req.body;

    if (!_totpCode) {
      return next(AppError.badRequest(
        'Critical action requires TOTP re-confirmation. Include _totpCode in request body.',
      ));
    }

    // Validate format: 6 digits exactly
    if (!/^\d{6}$/.test(String(_totpCode))) {
      return next(AppError.badRequest('Invalid TOTP code format — must be 6 digits'));
    }

    // Get user's TOTP secret from DB (never from JWT — resistance to token forging)
    const user = await User.findById(req.user.userId)
      .select('+twoFactorSecret twoFactorEnabled')   // +twoFactorSecret because field is select:false
      .lean();

    if (!user?.twoFactorEnabled || !user?.twoFactorSecret) {
      return next(AppError.forbidden(
        'Critical action requires 2FA. Enable 2FA first at /api/v1/auth/2fa/setup',
      ));
    }

    // ── STEP 1: TOTP Replay Prevention ──────────────────────────────────────────
    // Check BEFORE verifying the code — if the code is already used, reject immediately.
    // This prevents timing attacks where an attacker could learn whether the code
    // is valid before it gets deduplicated.
    //
    // Key: compound unique index {userId, code} ensures per-user code isolation.
    // A code "123456" used by admin A does NOT block "123456" from admin B.
    const dedupeKey = `${req.user.userId}:crit:${_totpCode}`;
    try {
      await UsedTotpCode.create({
        userId: req.user.userId,
        code:   dedupeKey,          // Namespace with userId already, but still scoped by compound indexed schema userId
        usedAt: new Date(),
      });
    } catch (dedupErr) {
      if (dedupErr.code === 11000) {
        // Code already used within the 90-second TTL window
        logger.warn('Critical action TOTP replay blocked', {
          userId: req.user.userId,
          role:   req.user.role,
          ip:     req.ip,
          path:   req.path,
        });
        return next(AppError.unauthorized(
          'TOTP code already used. Wait for your authenticator to generate a new code.',
        ));
      }
      // Non-duplicate DB error — fail safe: reject the request
      logger.error('confirmCriticalAction: UsedTotpCode insert failed', {
        error: dedupErr.message,
        userId: req.user.userId,
      });
      return next(AppError.internalError('Authentication system error'));
    }

    // ── STEP 2: TOTP Signature Verification ─────────────────────────────────────
    // Verify TOTP — window ±1 period (30s each) to account for clock skew.
    // The code is now already recorded in UsedTotpCode, so even if verification
    // fails, no replay is possible with this code (the record is already there).
    const isValid = speakeasy.totp.verify({
      secret:   user.twoFactorSecret,
      encoding: 'base32',
      token:    String(_totpCode),
      window:   1,
    });

    if (!isValid) {
      logger.warn('Critical action TOTP rejected — invalid code', {
        userId: req.user.userId,
        role:   req.user.role,
        ip:     req.ip,
        path:   req.path,
      });
      // Note: UsedTotpCode entry already written above. This means an invalid code
      // also consumes the code slot — intentional! Prevents brute-force: if attacker
      // guesses wrong, that guess is permanently burned within the TTL window.
      return next(AppError.unauthorized('Invalid TOTP code — critical action denied'));
    }

    // ── STEP 3: Sanitize request body ────────────────────────────────────────────
    // Remove _totpCode so it doesn't reach domain controllers or audit logs
    delete req.body._totpCode;

    next();
  } catch (err) {
    next(err);
  }
}

module.exports = { confirmCriticalAction };
