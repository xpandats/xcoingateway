'use strict';

/**
 * @module middleware/authorize — FIXED
 *
 * RBAC Authorization Middleware — Dual-mode: role OR permission check.
 *
 * FIX: The previous version called authorize('admin') passing a ROLE string,
 * but hasAllPermissions() checked it as a PERMISSION string ('admin'), which
 * doesn't exist in the RBAC matrix — causing all admin routes to return 403.
 *
 * FIX: authorize() now auto-detects whether the argument is a ROLE or PERMISSION:
 *   - ROLE: 'admin', 'super_admin', 'merchant', 'support'
 *   - PERMISSION: 'wallets:create', 'withdrawals:approve', etc.
 *
 * Role check: user's role must BE that role (or be super_admin, which has all)
 * Permission check: user's role must HAVE that permission in the RBAC matrix
 *
 * Usage:
 *   authorize('admin')              → requires admin or super_admin role
 *   authorize('super_admin')        → requires super_admin role ONLY
 *   authorize('wallets:create')     → requires the permission in RBAC matrix
 *   authorize('admin', 'wallets:create') → both must pass
 */

const { rbac, AppError, ErrorCodes } = require('@xcg/common');
const { ROLES } = require('@xcg/common').constants;

const VALID_ROLES = new Set(Object.values(ROLES));

/**
 * Check if a string is a role (not a resource:action permission).
 */
function isRoleString(str) {
  return VALID_ROLES.has(str);
}

/**
 * Check if user's role satisfies a single requirement.
 * @param {string} userRole - The user's actual role
 * @param {string} requirement - Role name OR 'resource:action' permission
 */
function satisfies(userRole, requirement) {
  if (isRoleString(requirement)) {
    // Role check: super_admin satisfies any role requirement
    if (userRole === ROLES.SUPER_ADMIN) return true;
    return userRole === requirement;
  }
  // Permission check via RBAC matrix
  return rbac.hasPermission(userRole, requirement);
}

/**
 * Authorization middleware factory.
 * ALL provided requirements must be satisfied (AND logic).
 *
 * @param {...string} requirements - Role names OR permission strings
 * @returns {Function} Express middleware
 */
function authorize(...requirements) {
  return (req, res, next) => {
    if (!req.user) {
      return next(AppError.unauthorized('Authentication required', ErrorCodes.AUTH_TOKEN_MISSING));
    }

    const { role } = req.user;

    const hasAccess = requirements.every((req_) => satisfies(role, req_));

    if (!hasAccess) {
      return next(AppError.forbidden(
        'Insufficient permissions',
        ErrorCodes.RBAC_INSUFFICIENT_PERMISSIONS,
      ));
    }

    next();
  };
}

/**
 * Accepts ANY of the specified requirements (OR logic).
 */
function authorizeAny(...requirements) {
  return (req, res, next) => {
    if (!req.user) {
      return next(AppError.unauthorized('Authentication required', ErrorCodes.AUTH_TOKEN_MISSING));
    }

    const { role } = req.user;
    const hasAccess = requirements.some((req_) => satisfies(role, req_));

    if (!hasAccess) {
      return next(AppError.forbidden('Insufficient permissions', ErrorCodes.RBAC_INSUFFICIENT_PERMISSIONS));
    }

    next();
  };
}

module.exports = { authorize, authorizeAny };
