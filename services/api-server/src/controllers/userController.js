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
const { validate, AppError, ErrorCodes } = require('@xcg/common');
const { User, AuditLog, RefreshToken } = require('@xcg/database');
const asyncHandler = require('../utils/asyncHandler');
const { config }   = require('../config');
const logger = require('@xcg/logger').createLogger('user-ctrl');
const crypto = require('crypto');

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

// ─── Helpers ─────────────────────────────────────────────────────────────────

function safeUser(user) {
  const obj = user.toObject ? user.toObject() : { ...user };
  delete obj.passwordHash;
  delete obj.twoFactorSecret;
  delete obj.__v;
  return obj;
}

// ─── Handlers ────────────────────────────────────────────────────────────────

async function listUsers(req, res) {
  const { page, limit, role, search } = validate(paginationSchema, req.query);

  const filter = { isActive: { $ne: false } };
  if (role)   filter.role   = role;
  if (search) filter.email  = { $regex: search, $options: 'i' };

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
    actor:      String(req.user._id),
    action:     'user.created',
    resource:   'user',
    resourceId: String(newUser._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { email: data.email, role: data.role },
  });

  logger.info('UserCtrl: user created', {
    adminId: String(req.user._id),
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
    actor:      String(req.user._id),
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

  const user = await User.findById(req.params.id);
  if (!user) throw AppError.notFound('User not found', ErrorCodes.USER_NOT_FOUND);

  // Cannot modify super_admin role
  if (user.role === 'super_admin') {
    throw AppError.forbidden('Cannot modify a super_admin role', ErrorCodes.USER_CANNOT_MODIFY_SUPER_ADMIN);
  }
  // Cannot target self (would lock out TOTP-validated admin)
  if (String(user._id) === String(req.user._id)) {
    throw AppError.forbidden('Cannot change your own role');
  }

  const previousRole = user.role;
  user.role = role;
  await user.save();

  await AuditLog.create({
    actor:      String(req.user._id),
    action:     'user.role_changed',
    resource:   'user',
    resourceId: String(user._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { previousRole, newRole: role },
  });

  logger.warn('UserCtrl: user role changed', {
    adminId:   String(req.user._id),
    userId:    String(user._id),
    from:      previousRole,
    to:        role,
  });

  res.json({ success: true, data: { user: safeUser(user), previousRole, newRole: role } });
}

async function lockUser(req, res) {
  const user = await User.findById(req.params.id);
  if (!user) throw AppError.notFound('User not found', ErrorCodes.USER_NOT_FOUND);

  if (user.role === 'super_admin') {
    throw AppError.forbidden('Cannot lock a super_admin account', ErrorCodes.USER_CANNOT_MODIFY_SUPER_ADMIN);
  }
  if (String(user._id) === String(req.user._id)) {
    throw AppError.forbidden('Cannot lock your own account');
  }

  user.isLocked       = true;
  user.lockedAt       = new Date();
  user.lockedReason   = req.body.reason || 'Admin action';
  user.loginAttempts  = 0;
  await user.save();

  // Revoke all sessions
  await RefreshToken.deleteMany({ userId: user._id });

  await AuditLog.create({
    actor:      String(req.user._id),
    action:     'user.locked',
    resource:   'user',
    resourceId: String(user._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { reason: user.lockedReason },
  });

  res.json({ success: true, message: 'User account locked. All active sessions revoked.' });
}

async function unlockUser(req, res) {
  const user = await User.findById(req.params.id);
  if (!user) throw AppError.notFound('User not found', ErrorCodes.USER_NOT_FOUND);

  user.isLocked      = false;
  user.lockedAt      = null;
  user.lockedReason  = '';
  user.loginAttempts = 0;
  user.lockUntil     = null;
  await user.save();

  await AuditLog.create({
    actor:      String(req.user._id),
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
  const user = await User.findById(req.params.id);
  if (!user) throw AppError.notFound('User not found', ErrorCodes.USER_NOT_FOUND);

  if (user.role === 'super_admin') {
    throw AppError.forbidden('Cannot deactivate a super_admin account', ErrorCodes.USER_CANNOT_MODIFY_SUPER_ADMIN);
  }
  if (String(user._id) === String(req.user._id)) {
    throw AppError.forbidden('Cannot deactivate your own account', ErrorCodes.USER_CANNOT_DELETE_SELF);
  }

  user.isActive    = false;
  user.deactivatedAt = new Date();
  user.deactivatedBy = req.user._id;
  await user.save();

  // Revoke all sessions
  await RefreshToken.deleteMany({ userId: user._id });

  await AuditLog.create({
    actor:      String(req.user._id),
    action:     'user.deactivated',
    resource:   'user',
    resourceId: String(user._id),
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { email: user.email, role: user.role },
  });

  logger.warn('UserCtrl: user deactivated', {
    adminId: String(req.user._id),
    userId:  String(user._id),
    email:   user.email,
  });

  res.json({ success: true, message: 'User account deactivated. All sessions revoked.' });
}

async function forceLogout(req, res) {
  const user = await User.findById(req.params.id).lean();
  if (!user) throw AppError.notFound('User not found', ErrorCodes.USER_NOT_FOUND);

  const result = await RefreshToken.deleteMany({ userId: new mongoose.Types.ObjectId(req.params.id) });

  await AuditLog.create({
    actor:      String(req.user._id),
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

// Need mongoose for ObjectId in forceLogout
const mongoose = require('mongoose');

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
};
