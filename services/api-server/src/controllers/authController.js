'use strict';

/**
 * @module controllers/authController
 *
 * Authentication Controller — Thin HTTP Layer.
 *
 * DESIGN PATTERN (Bank-Grade):
 *   Controller responsibilities:
 *     ✓ Parse and validate HTTP input (via Joi schemas)
 *     ✓ Call the appropriate service method
 *     ✓ Set HTTP-specific things (cookies, status codes)
 *     ✓ Return standardized JSON responses
 *
 *   Controller does NOT:
 *     ✗ Query the database directly
 *     ✗ Contain business logic
 *     ✗ Handle crypto operations
 *     ✗ Make decisions about authentication rules
 *
 * All business logic lives in authService.js.
 */

const { validate, schemas, response } = require('@xcg/common');
const { config } = require('../config');
const authService = require('../services/authService');

// ─── Cookie Helpers (HTTP-only concern) ──────────────────────

function _setRefreshCookie(res, token) {
  res.cookie('refreshToken', token, {
    httpOnly: true,
    // CSRF-3: Always secure — even in dev use HTTPS via mkcert/reverse proxy
    // HTTP is never acceptable for sensitive auth cookies
    secure: true,
    sameSite: 'strict',
    path: '/api/v1/auth/refresh',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

function _clearRefreshCookie(res) {
  const cookieOpts = { httpOnly: true, secure: true, sameSite: 'strict' };
  // S-2: Clear with BOTH paths — belt-and-suspenders.
  // If cookie was ever set with a different path (bug, migration), it won't
  // be cleared by a single path-specific clearCookie call.
  res.clearCookie('refreshToken', { ...cookieOpts, path: '/api/v1/auth/refresh' });
  res.clearCookie('refreshToken', { ...cookieOpts, path: '/' });
}

// ═══════════════════════════════════════════════════════════════
// REGISTER
// ═══════════════════════════════════════════════════════════════

exports.register = async (req, res, next) => {
  try {
    const data = validate(schemas.auth.register, req.body);
    const result = await authService.register(data);

    // SECURITY: Same response shape whether email exists or not
    // to prevent account enumeration.
    if (!result.isNew) {
      return res.status(201).json(
        response.success(null, 'If this email is not already registered, your account has been created. Pending admin approval.'),
      );
    }

    res.status(201).json(
      response.success(
        result.user.toSafeJSON(),
        'Account created. Pending admin approval before you can operate.',
      ),
    );
  } catch (err) {
    next(err);
  }
};

// ═══════════════════════════════════════════════════════════════
// LOGIN
// ═══════════════════════════════════════════════════════════════

exports.login = async (req, res, next) => {
  try {
    const data = validate(schemas.auth.login, req.body);
    const result = await authService.login(data, req.ip, req.get('user-agent'));

    _setRefreshCookie(res, result.refreshToken);

    res.json(response.success({
      user: result.user.toSafeJSON(),
      accessToken: result.accessToken,
      expiresIn: config.jwt.accessExpiry,
    }));
  } catch (err) {
    next(err);
  }
};

// ═══════════════════════════════════════════════════════════════
// LOGOUT
// ═══════════════════════════════════════════════════════════════

exports.logout = async (req, res, next) => {
  try {
    await authService.logout(req.cookies.refreshToken, req.user.userId);
    _clearRefreshCookie(res);
    res.json(response.success(null, 'Logged out successfully'));
  } catch (err) {
    next(err);
  }
};

// ═══════════════════════════════════════════════════════════════
// LOGOUT ALL SESSIONS
// ═══════════════════════════════════════════════════════════════

exports.logoutAll = async (req, res, next) => {
  try {
    await authService.logoutAll(req.user.userId);
    _clearRefreshCookie(res);
    res.json(response.success(null, 'All sessions terminated'));
  } catch (err) {
    next(err);
  }
};

// ═══════════════════════════════════════════════════════════════
// REFRESH TOKEN
// ═══════════════════════════════════════════════════════════════

exports.refresh = async (req, res, next) => {
  try {
    const result = await authService.refreshTokens(
      req.cookies.refreshToken,
      req.ip,
      req.get('user-agent'),
    );

    _setRefreshCookie(res, result.refreshToken);

    res.json(response.success({
      accessToken: result.accessToken,
      expiresIn: config.jwt.accessExpiry,
    }));
  } catch (err) {
    next(err);
  }
};

// ═══════════════════════════════════════════════════════════════
// CHANGE PASSWORD
// ═══════════════════════════════════════════════════════════════

exports.changePassword = async (req, res, next) => {
  try {
    const data = validate(schemas.auth.changePassword, req.body);
    await authService.changePassword(req.user.userId, data.currentPassword, data.newPassword);
    _clearRefreshCookie(res);
    res.json(response.success(null, 'Password changed. All sessions have been terminated. Please log in again.'));
  } catch (err) {
    next(err);
  }
};

// ═══════════════════════════════════════════════════════════════
// GET ME (Profile)
// ═══════════════════════════════════════════════════════════════

exports.me = async (req, res, next) => {
  try {
    const profile = await authService.getProfile(req.user.userId);
    res.json(response.success(profile));
  } catch (err) {
    next(err);
  }
};

// ═══════════════════════════════════════════════════════════════
// 2FA SETUP
// ═══════════════════════════════════════════════════════════════

exports.setup2FA = async (req, res, next) => {
  try {
    const result = await authService.setup2FA(req.user.userId);
    res.json(response.success({
      secret: result.secret,
      otpAuthUrl: result.otpAuthUrl,
      warning: 'Save this secret securely. It will NOT be shown again.',
    }));
  } catch (err) {
    next(err);
  }
};

// ═══════════════════════════════════════════════════════════════
// 2FA VERIFY (Enable)
// ═══════════════════════════════════════════════════════════════

exports.verify2FA = async (req, res, next) => {
  try {
    const data = validate(schemas.auth.verify2fa, req.body);
    await authService.verify2FA(req.user.userId, data.totpCode);
    res.json(response.success(null, '2FA enabled successfully'));
  } catch (err) {
    next(err);
  }
};

// ═══════════════════════════════════════════════════════════════
// 2FA DISABLE
// ═══════════════════════════════════════════════════════════════

exports.disable2FA = async (req, res, next) => {
  try {
    const data = validate(schemas.auth.verify2fa, req.body);
    await authService.disable2FA(req.user.userId, data.totpCode);
    res.json(response.success(null, '2FA disabled successfully'));
  } catch (err) {
    next(err);
  }
};
