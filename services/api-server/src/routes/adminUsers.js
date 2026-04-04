'use strict';

/**
 * @module routes/adminUsers
 *
 * Admin User Management Routes.
 *
 * Security Stack:
 *   1. authenticate()      — JWT verification
 *   2. authorize('admin')  — Admin role
 *   3. require2FA()        — 2FA must be enabled
 *   4. adminIpWhitelist()  — IP must be on whitelist
 *
 * Critical actions additionally require:
 *   5. confirmCriticalAction — Live TOTP code in request body
 *
 * Deactivation requires super_admin role (enforced by separate middleware stack).
 *
 * Mounted at: /admin/users
 */

const router = require('express').Router();
const asyncHandler             = require('../utils/asyncHandler');
const { authenticate }         = require('../middleware/authenticate');
const { authorize }            = require('../middleware/authorize');
const { require2FA }           = require('../middleware/require2FA');
const { adminIpWhitelist }     = require('../middleware/adminIpWhitelist');
const { confirmCriticalAction }= require('../middleware/confirmCriticalAction');

const {
  listUsers, getUser, createUser, updateUser,
  changeUserRole, lockUser, unlockUser, deactivateUser, forceLogout,
} = require('../controllers/userController');

// Standard admin 4-layer security
const adminAuth      = [authenticate, authorize('admin'), require2FA, adminIpWhitelist()];
// Super-admin only (for destructive ops like deactivation)
const superAdminAuth = [authenticate, authorize('super_admin'), require2FA, adminIpWhitelist()];

// ─── Read operations ─────────────────────────────────────────────────────────
router.get('/',           adminAuth, asyncHandler(listUsers));
router.get('/:id',        adminAuth, asyncHandler(getUser));

// ─── Create ──────────────────────────────────────────────────────────────────
router.post('/',          adminAuth, asyncHandler(createUser));

// ─── Update (non-critical) ───────────────────────────────────────────────────
router.put('/:id',        adminAuth, asyncHandler(updateUser));

// ─── Critical: role change, lock, unlock, force-logout ───────────────────────
// All require TOTP re-confirmation
router.put('/:id/role',
  adminAuth,
  confirmCriticalAction,
  asyncHandler(changeUserRole),
);

router.post('/:id/lock',
  adminAuth,
  confirmCriticalAction,
  asyncHandler(lockUser),
);

router.post('/:id/unlock',
  adminAuth,
  confirmCriticalAction,
  asyncHandler(unlockUser),
);

router.post('/:id/force-logout',
  adminAuth,
  confirmCriticalAction,
  asyncHandler(forceLogout),
);

// ─── Deactivate — super_admin only + TOTP ────────────────────────────────────
router.delete('/:id',
  superAdminAuth,
  confirmCriticalAction,
  asyncHandler(deactivateUser),
);

module.exports = router;
