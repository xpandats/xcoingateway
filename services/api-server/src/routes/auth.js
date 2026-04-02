'use strict';

/**
 * Authentication Routes.
 *
 * POST /api/v1/auth/register     — Register new user
 * POST /api/v1/auth/login        — Login (returns access + refresh tokens)
 * POST /api/v1/auth/logout       — Logout (invalidate refresh token)
 * POST /api/v1/auth/refresh      — Refresh access token
 * POST /api/v1/auth/2fa/setup    — Setup 2FA (returns QR code URI)
 * POST /api/v1/auth/2fa/verify   — Verify and enable 2FA
 * POST /api/v1/auth/2fa/disable  — Disable 2FA
 * GET  /api/v1/auth/me           — Get current user profile
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
router.get('/me', authenticate, authController.me);
router.post('/2fa/setup', authenticate, authController.setup2FA);
router.post('/2fa/verify', authenticate, authController.verify2FA);
router.post('/2fa/disable', authenticate, authController.disable2FA);

module.exports = router;
