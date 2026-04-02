'use strict';

/**
 * RBAC Authorization Middleware.
 *
 * Checks if the authenticated user has the required permission(s).
 * Must be used AFTER the authenticate middleware.
 *
 * Usage:
 *   router.get('/wallets', authenticate, authorize('wallets:read'), controller);
 *   router.post('/wallets', authenticate, authorize('wallets:create'), controller);
 */

const { rbac, AppError, ErrorCodes } = require('@xcg/common');

/**
 * Create authorization middleware for a specific permission.
 *
 * @param {...string} requiredPermissions - Permission(s) required (all must be present)
 * @returns {Function} Express middleware
 */
function authorize(...requiredPermissions) {
  return (req, res, next) => {
    if (!req.user) {
      return next(AppError.unauthorized('Authentication required', ErrorCodes.AUTH_TOKEN_MISSING));
    }

    const { role } = req.user;

    const hasAccess = rbac.hasAllPermissions(role, requiredPermissions);

    if (!hasAccess) {
      return next(AppError.forbidden(
        `Insufficient permissions. Required: ${requiredPermissions.join(', ')}`,
        ErrorCodes.RBAC_INSUFFICIENT_PERMISSIONS,
      ));
    }

    next();
  };
}

/**
 * Create authorization middleware that accepts ANY of the specified permissions.
 *
 * @param {...string} permissions - At least one must be present
 * @returns {Function} Express middleware
 */
function authorizeAny(...permissions) {
  return (req, res, next) => {
    if (!req.user) {
      return next(AppError.unauthorized('Authentication required', ErrorCodes.AUTH_TOKEN_MISSING));
    }

    const { role } = req.user;
    const hasAccess = rbac.hasAnyPermission(role, permissions);

    if (!hasAccess) {
      return next(AppError.forbidden(
        'Insufficient permissions',
        ErrorCodes.RBAC_INSUFFICIENT_PERMISSIONS,
      ));
    }

    next();
  };
}

module.exports = { authorize, authorizeAny };
