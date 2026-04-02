'use strict';

/**
 * RBAC (Role-Based Access Control) Permission Matrix.
 *
 * Defines exactly what each role can do.
 * Checked at middleware level BEFORE any business logic.
 *
 * Format: resource:action
 * Wildcard (*) means all actions on that resource.
 */

const { ROLES } = require('./constants');

/**
 * Permission definitions per role.
 * Each permission is a string in format "resource:action".
 */
const PERMISSIONS = Object.freeze({
  [ROLES.ADMIN]: Object.freeze([
    // Full system access
    'users:*',
    'merchants:*',
    'wallets:*',
    'invoices:*',
    'transactions:*',
    'withdrawals:*',
    'disputes:*',
    'config:*',
    'audit:read',
    'dashboard:*',
    'reconciliation:*',
    'fraud:*',
  ]),

  [ROLES.MERCHANT]: Object.freeze([
    // Own data only (enforced at query level)
    'invoices:create',
    'invoices:read',
    'invoices:cancel',
    'transactions:read',
    'withdrawals:create',
    'withdrawals:read',
    'disputes:create',
    'disputes:read',
    'disputes:respond',
    'merchants:read_own',
    'merchants:update_own',
    'merchants:apikey_create',
    'merchants:apikey_revoke',
    'merchants:webhook_update',
    'dashboard:read_own',
  ]),

  [ROLES.SUPPORT]: Object.freeze([
    // Read-only access, can escalate disputes
    'merchants:read',
    'invoices:read',
    'transactions:read',
    'withdrawals:read',
    'disputes:read',
    'disputes:escalate',
    'audit:read',
    'dashboard:read',
  ]),
});

/**
 * Check if a role has a specific permission.
 *
 * @param {string} role - User role (admin, merchant, support)
 * @param {string} permission - Permission to check (e.g., 'wallets:create')
 * @returns {boolean} true if role has the permission
 */
function hasPermission(role, permission) {
  const rolePermissions = PERMISSIONS[role];
  if (!rolePermissions) return false;

  const [resource, action] = permission.split(':');

  return rolePermissions.some((perm) => {
    const [permResource, permAction] = perm.split(':');
    // Exact match or wildcard
    if (permResource === resource && (permAction === '*' || permAction === action)) {
      return true;
    }
    return false;
  });
}

/**
 * Check if a role has ALL of the specified permissions.
 *
 * @param {string} role - User role
 * @param {string[]} permissions - Array of permissions to check
 * @returns {boolean} true only if ALL permissions are granted
 */
function hasAllPermissions(role, permissions) {
  return permissions.every((perm) => hasPermission(role, perm));
}

/**
 * Check if a role has ANY of the specified permissions.
 *
 * @param {string} role - User role
 * @param {string[]} permissions - Array of permissions to check
 * @returns {boolean} true if at least one permission is granted
 */
function hasAnyPermission(role, permissions) {
  return permissions.some((perm) => hasPermission(role, perm));
}

/**
 * Get all permissions for a role.
 *
 * @param {string} role - User role
 * @returns {string[]} Array of permission strings
 */
function getPermissions(role) {
  return PERMISSIONS[role] || [];
}

module.exports = {
  PERMISSIONS,
  hasPermission,
  hasAllPermissions,
  hasAnyPermission,
  getPermissions,
};
