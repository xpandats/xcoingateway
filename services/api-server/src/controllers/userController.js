'use strict';

/**
 * @module controllers/userController
 *
 * Admin User Management — Create and manage admin/support user accounts.
 *
 * All operations are audit-logged, and critical mutations (role change,
 * lock/unlock, deactivate, force-logout) require TOTP re-confirmation.
 *
 * Routes (mounted at /admin/users):
 *   GET    /                    — List all users
 *   GET    /:id                 — Get user details
 *   POST   /                    — Create admin/support user
 *   PUT    /:id                 — Update user info
 *   PUT    /:id/role            — Change role (TOTP)
 *   POST   /:id/lock            — Lock account (TOTP)
 *   POST   /:id/unlock          — Unlock account (TOTP)
 *   DELETE /:id                 — Deactivate user (TOTP, super_admin only)
 *   POST   /:id/force-logout    — Revoke all sessions (TOTP)
 */

const Joi      = require('joi');
const bcrypt   = require('bcrypt');
const mongoose = require('mongoose');  // MUST be at top — used in forceLogout
const { validate, AppError, ErrorCodes } = require('@xcg/common');
const { User, AuditLog, RefreshToken } = require('@xcg/database');
const asyncHandler = require('../utils/asyncHandler');
const { config }   = require('../config');
const logger = require('@xcg/logger').createLogger('user-ctrl');
const crypto = require('crypto');
const { revokeJti } = require('../middleware/authenticate');

// Helper: safe regex escape to prevent ReDoS via search param
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Helper: validate MongoDB ObjectId format before querying
function assertValidObjectId(id, label = 'id') {
  if (!mongoose.Types.ObjectId.isValid(id)) {
    throw AppError.badRequest(`Invalid ${label} format`);
  }
}

// ─── Validation ──────────────────────────────────────────────────────────────

const ALLOWED_ROLES = ['admin', 'support', 'super_admin'];

const createUserSchema = Joi.object({
  email:    Joi.string().email().lowercase().required(),
  password: Joi.string().min(12).max(128).required(),
  role:     Joi.string().valid('admin', 'support').required(), // Cannot create super_admin via API
  name:     Joi.string().trim().min(2).max(100).optional(),
}).options({ stripUnknown: true });

const updateUserSchema = Joi.object({
  name:  Joi.string().trim().min(2).max(100).optional(),
  email: Joi.string().email().lowercase().optional(),
}).options({ stripUnknown: true });

const changeRoleSchema = Joi.object({
  role: Joi.string().valid('admin', 'support').required(), // Cannot promote to super_admin via API
}).options({ stripUnknown: true });

const paginationSchema = Joi.object({
  page:   Joi.number().integer().min(1).default(1),
  limit:  Joi.number().integer().min(1).max(100).default(20),
  role:   Joi.string().valid('admin', 'support', 'super_admin', 'merchant').optional(),
  search: Joi.string().trim().max(100).optional(),
}).options({ stripUnknown: true });

// Helper: strip sensitive fields before API response
function safeUser(user) {
  const obj = user.toObject ? user.toObject() : { ...user };
  delete obj.passwordHash;
  delete obj.twoFactorSecret;
  delete obj.passwordHistory;
  delete obj.__v;
  return obj;
}

// Helper: extract actorId from req.user (authenticate sets userId, not _id)
function actorId(req) {
  return req.user.userId || String(req.user._id);
}

// ─── Handlers ────────────────────────────────────────────────────────────────

async function listUsers(req, res) {
  const { page, limit, role, search } = validate(paginationSchema, req.query);

  const filter = { isActive: { $ne: false } };
  if (role)   filter.role   = role;
  // H1 FIX: Escape regex to prevent ReDoS
  if (search) filter.email  = { $regex: escapeRegex(search), $options: 'i' };

  const [users, total] = await Promise.all([
    User.find(filter)
      .select('-passwordHash -twoFactorSecret -__v')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(),
    User.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data: { users, pagination: { page, limit, total, pages: Math.ceil(total / limit) } },
  });
}

async function getUser(req, res) {
  assertValidObjectId(req.params.id, 'userId');
  const user = await User.findById(req.params.id)
    .select('-passwordHash -twoFactorSecret -__v')
    .lean();
  if (!user) throw AppError.notFound('User not found', ErrorCodes.USER_NOT_FOUND);

  res.json({ success: true, data: { user } });
}

async function createUser(req, res) {
  const data = validate(createUserSchema, req.body);

  // Cannot create super_admin via API
  if (data.role === 'super_admin') {
    throw AppError.forbidden('super_admin accounts cannot be created via the API');
  }

  const existing = await User.findOne({ email: data.email }).lean();
  if (existing) throw AppError.conflict('A user with this email already exists', ErrorCodes.USER_ALREADY_EXISTS);

  const passwordHash = await bcrypt.hash(data.password, config.bcrypt.saltRounds || 12);

  const newUser = await User.create({
    email:        data.email,
    passwordHash,
    role:         data.role,
    name:         data.name || '',
    isActive:     true,
    twoFactorEnabled: false,
    createdAt:    new Date(),
  });

  await AuditLog.create({
    actor:      actorId(req),
    action:     'user.created',
    resource:   'user',
    resourceId: String(newUser._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { email: data.email, role: data.role },
  });

  logger.info('UserCtrl: user created', {
    adminId: actorId(req),
    newUserId: String(newUser._id),
    role: data.role,
  });

  res.status(201).json({
    success: true,
    data: { user: safeUser(newUser) },
  });
}

async function updateUser(req, res) {
  const data = validate(updateUserSchema, req.body);

  assertValidObjectId(req.params.id, 'userId');
  const user = await User.findById(req.params.id);
  if (!user) throw AppError.notFound('User not found', ErrorCodes.USER_NOT_FOUND);

  // Cannot modify super_admin (unless you ARE super_admin, enforced by routes)
  if (user.role === 'super_admin' && req.user.role !== 'super_admin') {
    throw AppError.forbidden('Cannot modify a super_admin account', ErrorCodes.USER_CANNOT_MODIFY_SUPER_ADMIN);
  }

  if (data.email && data.email !== user.email) {
    const exists = await User.findOne({ email: data.email }).lean();
    if (exists) throw AppError.conflict('Email already in use');
  }

  Object.assign(user, data);
  await user.save();

  await AuditLog.create({
    actor:      actorId(req),
    action:     'user.updated',
    resource:   'user',
    resourceId: String(user._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { fields: Object.keys(data) },
  });

  res.json({ success: true, data: { user: safeUser(user) } });
}

async function changeUserRole(req, res) {
  const { role } = validate(changeRoleSchema, req.body);

  assertValidObjectId(req.params.id, 'userId');
  const user = await User.findById(req.params.id);
  if (!user) throw AppError.notFound('User not found', ErrorCodes.USER_NOT_FOUND);

  // Cannot modify super_admin role
  if (user.role === 'super_admin') {
    throw AppError.forbidden('Cannot modify a super_admin role', ErrorCodes.USER_CANNOT_MODIFY_SUPER_ADMIN);
  }
  // Cannot target self
  if (String(user._id) === actorId(req)) {
    throw AppError.forbidden('Cannot change your own role');
  }

  const previousRole = user.role;
  user.role = role;
  await user.save();

  // Role change immediately revokes all sessions — force re-login with new permissions
  await RefreshToken.deleteMany({ userId: user._id });

  await AuditLog.create({
    actor:      actorId(req),
    action:     'user.role_changed',
    resource:   'user',
    resourceId: String(user._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { previousRole, newRole: role },
  });

  logger.warn('UserCtrl: user role changed', {
    adminId:   actorId(req),
    userId:    String(user._id),
    from:      previousRole,
    to:        role,
  });

  res.json({ success: true, data: { user: safeUser(user), previousRole, newRole: role, sessionsRevoked: true } });
}

async function lockUser(req, res) {
  assertValidObjectId(req.params.id, 'userId');
  const user = await User.findById(req.params.id);
  if (!user) throw AppError.notFound('User not found', ErrorCodes.USER_NOT_FOUND);

  if (user.role === 'super_admin') {
    throw AppError.forbidden('Cannot lock a super_admin account', ErrorCodes.USER_CANNOT_MODIFY_SUPER_ADMIN);
  }
  if (String(user._id) === actorId(req)) {
    throw AppError.forbidden('Cannot lock your own account');
  }

  // C3 FIX: User model uses failedLoginAttempts not loginAttempts
  // Set lockUntil to far future (effectively permanent lock until admin unlocks)
  user.failedLoginAttempts = 0;
  user.lockUntil           = new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000); // 100 years
  await user.save();

  // Revoke all sessions
  await RefreshToken.deleteMany({ userId: user._id });

  await AuditLog.create({
    actor:      actorId(req),
    action:     'user.locked',
    resource:   'user',
    resourceId: String(user._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { reason: req.body?.reason || 'Admin action' },
  });

  res.json({ success: true, message: 'User account locked. All active sessions revoked.' });
}

async function unlockUser(req, res) {
  assertValidObjectId(req.params.id, 'userId');
  const user = await User.findById(req.params.id);
  if (!user) throw AppError.notFound('User not found', ErrorCodes.USER_NOT_FOUND);

  // C3 FIX: Clear lockUntil (the actual lock mechanism in User model)
  user.failedLoginAttempts = 0;
  user.totpFailedAttempts  = 0;
  user.lockUntil           = null;
  await user.save();

  await AuditLog.create({
    actor:      actorId(req),
    action:     'user.unlocked',
    resource:   'user',
    resourceId: String(user._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
  });

  res.json({ success: true, message: 'User account unlocked.' });
}

async function deactivateUser(req, res) {
  assertValidObjectId(req.params.id, 'userId');
  const user = await User.findById(req.params.id);
  if (!user) throw AppError.notFound('User not found', ErrorCodes.USER_NOT_FOUND);

  if (user.role === 'super_admin') {
    throw AppError.forbidden('Cannot deactivate a super_admin account', ErrorCodes.USER_CANNOT_MODIFY_SUPER_ADMIN);
  }
  if (String(user._id) === actorId(req)) {
    throw AppError.forbidden('Cannot deactivate your own account', ErrorCodes.USER_CANNOT_DELETE_SELF);
  }

  // C3 FIX: User model uses standard isActive — set lockUntil too so any cached tokens also fail
  user.isActive  = false;
  user.lockUntil = new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000);
  await user.save();

  // Revoke all sessions
  await RefreshToken.deleteMany({ userId: user._id });

  await AuditLog.create({
    actor:      actorId(req),
    action:     'user.deactivated',
    resource:   'user',
    resourceId: String(user._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { email: user.email, role: user.role },
  });

  logger.warn('UserCtrl: user deactivated', {
    adminId: actorId(req),
    userId:  String(user._id),
    email:   user.email,
  });

  res.json({ success: true, message: 'User account deactivated. All sessions revoked.' });
}

async function forceLogout(req, res) {
  // C1 FIX: ObjectId validation before DB query (mongoose was previously required after module.exports)
  assertValidObjectId(req.params.id, 'userId');
  const user = await User.findById(req.params.id).lean();
  if (!user) throw AppError.notFound('User not found', ErrorCodes.USER_NOT_FOUND);

  const result = await RefreshToken.deleteMany({ userId: new mongoose.Types.ObjectId(req.params.id) });

  await AuditLog.create({
    actor:      actorId(req),
    action:     'user.force_logout',
    resource:   'user',
    resourceId: String(user._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { sessionsRevoked: result.deletedCount },
  });

  res.json({
    success: true,
    data: {
      message:         'All active sessions revoked.',
      sessionsRevoked: result.deletedCount,
    },
  });
}

/**
 * POST /admin/users/:id/revoke-token
 *
 * Emergency revoke a SPECIFIC active JWT access token by its jti.
 *
 * WHY THIS EXISTS:
 *   A user's access token is valid for 15 minutes even after forceLogout() revokes
 *   their refresh tokens — because the access token is stateless (JWT). In a breach
 *   scenario where a specific token is stolen (e.g., from a log, traffic capture, or
 *   endpoint compromise), those 15 minutes represent a real attack window.
 *
 *   This endpoint adds the jti to the Redis blocklist with TTL = access token lifetime,
 *   making that specific token immediately rejected by authenticate middleware.
 *
 * REQUEST BODY: { jti: "<hex>", reason: "<admin note>" }
 * Requires: superAdminAuth + confirmCriticalAction (defined in route)
 *
 * NOTE: The jti is obtained from:
 *   - The user's active session list (if exposed)
 *   - Audit log entries (if jti is logged on use)
 *   - The affected user's report of their last token
 *   - Traffic analysis during an incident investigation
 */
async function revokeToken(req, res) {
  const { jti, reason } = req.body;

  if (!jti || typeof jti !== 'string' || !/^[0-9a-f]{32}$/.test(jti)) {
    throw AppError.badRequest('Invalid jti format — must be 32-character hex string');
  }
  if (!reason || !String(reason).trim()) {
    throw AppError.badRequest('Reason is required for token revocation audit trail');
  }

  assertValidObjectId(req.params.id, 'userId');
  const user = await User.findById(req.params.id).lean();
  if (!user) throw AppError.notFound('User not found', ErrorCodes.USER_NOT_FOUND);

  const redis = req.app.locals.redis;
  if (!redis) {
    throw AppError.internalError('Redis unavailable — cannot write JTI blocklist. Token revocation requires Redis.');
  }

  // Blocklist this specific jti for the access token lifetime
  const accessTokenTtl = parseInt(config.jwt.accessExpiry, 10) || 900; // 15 min default
  await revokeJti(redis, jti, Math.floor(Date.now() / 1000) + accessTokenTtl);

  // Also revoke all refresh tokens (belt-and-suspenders)
  const result = await RefreshToken.deleteMany({ userId: new mongoose.Types.ObjectId(req.params.id) });

  await AuditLog.create({
    actor:      actorId(req),
    action:     'user.token_revoked',
    resource:   'user',
    resourceId: String(user._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { jti, reason: String(reason).trim(), refreshTokensRevoked: result.deletedCount },
  });

  logger.warn('UserCtrl: specific JWT revoked by admin', {
    adminId: actorId(req),
    userId:  String(user._id),
    jti,
    reason:  String(reason).trim(),
  });

  res.json({
    success: true,
    data: {
      message:              'Token blocklisted. The specific JWT is immediately invalid.',
      jti,
      refreshTokensRevoked: result.deletedCount,
      blockedForSeconds:    accessTokenTtl,
    },
  });
}


// C1 FIX: mongoose is now required at TOP of file (line 25)

module.exports = {
  listUsers:      asyncHandler(listUsers),
  getUser:        asyncHandler(getUser),
  createUser:     asyncHandler(createUser),
  updateUser:     asyncHandler(updateUser),
  changeUserRole: asyncHandler(changeUserRole),
  lockUser:       asyncHandler(lockUser),
  unlockUser:     asyncHandler(unlockUser),
  deactivateUser: asyncHandler(deactivateUser),
  forceLogout:    asyncHandler(forceLogout),
  revokeToken:    asyncHandler(revokeToken),
};

