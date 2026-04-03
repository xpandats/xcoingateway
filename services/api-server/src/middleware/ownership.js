'use strict';

/**
 * @module middleware/ownership
 *
 * Resource Ownership Enforcement — Bank-Grade.
 *
 * G1 FIX: RBAC checks PERMISSION (e.g., 'invoices:read') but NOT OWNERSHIP.
 * A merchant with 'invoices:read' could query any merchant's invoices
 * if service layer doesn't filter by merchantId.
 *
 * This middleware provides:
 *   1. assertMerchantOwnership() — Require merchantId match for merchant API requests
 *   2. buildMerchantFilter()    — Inject merchantId into all DB queries automatically
 *   3. assertOwnResource()      — Require userId match for user-scoped resources
 *
 * USAGE:
 *   // In route: merchant can only access their own data
 *   router.get('/invoices', authenticate, authorize('invoices:read'), buildMerchantFilter, invoiceController.list);
 *
 *   // In service: always use the injected filter
 *   const invoices = await Invoice.find(req.ownershipFilter);
 */

const { AppError, ErrorCodes, constants } = require('@xcg/common');
const { ROLES } = constants;

/**
 * Middleware: Inject ownership filter into req.ownershipFilter.
 *
 * For merchant auth (HMAC): filter by merchant._id
 * For JWT merchant users:   filter by user.merchantId
 * For admin/support:        no filter (can see all) — but use carefully
 *
 * MUST be applied to every merchant-facing data endpoint.
 * Services MUST use req.ownershipFilter in all DB queries.
 */
function buildMerchantFilter(req, _res, next) {
  const role = req.user?.role;

  if (role === ROLES.ADMIN || role === ROLES.SUPER_ADMIN || role === ROLES.SUPPORT) {
    // Admins see everything — no ownership filter
    req.ownershipFilter = {};
    return next();
  }

  // Merchant JWT auth
  if (role === ROLES.MERCHANT) {
    const merchantId = req.user?.merchantId;
    if (!merchantId) {
      return next(AppError.forbidden(
        'Merchant account not linked to this user',
        ErrorCodes.RBAC_INSUFFICIENT_PERMISSIONS,
      ));
    }
    req.ownershipFilter = { merchantId };
    return next();
  }

  // Merchant HMAC auth (no JWT role — req.merchant set by merchantAuth middleware)
  if (req.merchant?.merchantId) {
    req.ownershipFilter = { merchantId: req.merchant.merchantId };
    return next();
  }

  return next(AppError.forbidden('Cannot determine resource ownership', ErrorCodes.RBAC_INSUFFICIENT_PERMISSIONS));
}

/**
 * Assert the currently authenticated merchant owns a specific resource.
 * Call this in service layer when loading a single resource by ID.
 *
 * @param {object} resource - Loaded Mongoose document (must have .merchantId)
 * @param {object} req - Express request
 * @throws {AppError} 403 if ownership mismatch
 */
function assertMerchantOwnership(resource, req) {
  const role = req.user?.role;

  // Admins and support can access any resource
  if (role === ROLES.ADMIN || role === ROLES.SUPER_ADMIN || role === ROLES.SUPPORT) return;

  const actorMerchantId = req.user?.merchantId || req.merchant?.merchantId;
  if (!actorMerchantId) {
    throw AppError.forbidden('Cannot determine merchant identity', ErrorCodes.RBAC_INSUFFICIENT_PERMISSIONS);
  }

  const resourceMerchantId = resource.merchantId?.toString();
  if (resourceMerchantId !== actorMerchantId.toString()) {
    throw AppError.forbidden('Access denied: resource belongs to a different merchant', ErrorCodes.RBAC_INSUFFICIENT_PERMISSIONS);
  }
}

/**
 * Assert the authenticated user is accessing their own user record.
 *
 * @param {string} resourceUserId - The userId on the resource
 * @param {object} req - Express request
 * @throws {AppError} 403 if userId mismatch
 */
function assertOwnResource(resourceUserId, req) {
  const role = req.user?.role;
  if (role === ROLES.ADMIN || role === ROLES.SUPER_ADMIN) return;

  if (resourceUserId?.toString() !== req.user?.userId) {
    throw AppError.forbidden('Access denied: you can only access your own resources', ErrorCodes.RBAC_INSUFFICIENT_PERMISSIONS);
  }
}

module.exports = { buildMerchantFilter, assertMerchantOwnership, assertOwnResource };
