'use strict';

/**
 * Authentication Routes.
 *
 * PUBLIC:
 *   POST /api/v1/auth/register       — Register new merchant account (pending approval)
 *   POST /api/v1/auth/login          — Login (returns access + refresh tokens)
 *   POST /api/v1/auth/refresh         — Rotate refresh token + get new access token
 *
 * PROTECTED (requires valid access token):
 *   POST /api/v1/auth/logout          — Revoke current refresh token
 *   POST /api/v1/auth/logout-all      — Revoke ALL refresh tokens (all sessions)
 *   POST /api/v1/auth/change-password — Change password (revokes all sessions)
 *   GET  /api/v1/auth/me              — Get current user profile
 *   POST /api/v1/auth/2fa/setup       — Setup 2FA (returns TOTP secret + QR URI)
 *   POST /api/v1/auth/2fa/verify      — Verify TOTP code and enable 2FA
 *   POST /api/v1/auth/2fa/disable     — Disable 2FA (requires valid TOTP code)
 */

const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authenticate } = require('../middleware/authenticate');

// Public routes
router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/refresh', authController.refresh);

// Protected routes
router.post('/logout', authenticate, authController.logout);
router.post('/logout-all', authenticate, authController.logoutAll);
router.post('/change-password', authenticate, authController.changePassword);
router.get('/me', authenticate, authController.me);
router.post('/2fa/setup', authenticate, authController.setup2FA);
router.post('/2fa/verify', authenticate, authController.verify2FA);
router.post('/2fa/disable', authenticate, authController.disable2FA);

module.exports = router;
