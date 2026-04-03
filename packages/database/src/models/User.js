'use strict';

/**
 * @module models/User
 *
 * User — Authentication and authorization identities.
 *
 * SECURITY:
 *   - Sensitive fields (passwordHash, twoFactorSecret, passwordHistory)
 *     are excluded from ALL queries by default (select: false).
 *   - To fetch them, use explicit .select('+passwordHash') opt-in.
 *   - This prevents .lean() bypass of toSafeJSON().
 */

const mongoose = require('mongoose');
const { ROLES } = require('@xcg/common').constants;
const { secureFieldsPlugin } = require('../plugins/secureFields');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },

  // SECURITY: select:false — never returned unless explicitly requested with +passwordHash
  passwordHash: {
    type: String,
    required: true,
    select: false,
    // DB-level validation: must be a bcrypt hash (starts with $2b$)
    validate: {
      validator: (v) => typeof v === 'string' && v.startsWith('$2b$'),
      message: 'SECURITY: passwordHash must be a bcrypt hash (starts with $2b$)',
    },
  },

  firstName: { type: String, required: true, trim: true },
  lastName: { type: String, required: true, trim: true },
  role: { type: String, enum: Object.values(ROLES), required: true, index: true },
  isActive: { type: Boolean, default: true, index: true },

  // Admin approval (merchants require approval before they can operate)
  isApproved: { type: Boolean, default: false },
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  approvedAt: { type: Date, default: null },

  // 2FA (select:false — never returned in normal queries)
  twoFactorSecret: { type: String, default: null, select: false }, // Encrypted TOTP secret
  twoFactorEnabled: { type: Boolean, default: false },

  // Security
  failedLoginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date, default: null },
  lastLoginAt: { type: Date, default: null },
  lastLoginIp: { type: String, default: null },       // Stored as SHA-256 hash for privacy
  passwordChangedAt: { type: Date, default: null },

  // Password history (select:false — internal use only)
  passwordHistory: { type: [String], default: [], select: false },

  // Merchant reference (if role is merchant)
  merchantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant', default: null },
}, {
  timestamps: true,
  collection: 'users',
  strict: true,
});

// Indexes
userSchema.index({ email: 1, isActive: 1 });
userSchema.index({ role: 1, isActive: 1 });

// Apply secure fields plugin (redundant with select:false above but adds findOne/find hooks)
// Kept for belt-and-suspenders and future developer protection
userSchema.plugin(secureFieldsPlugin, {
  sensitiveFields: ['passwordHash', 'twoFactorSecret', 'passwordHistory'],
});

// Virtual: is account locked?
userSchema.virtual('isLocked').get(function () {
  if (!this.lockUntil) return false;
  return this.lockUntil > Date.now(); // true if lock is still active
});

// NEVER return sensitive fields in JSON
userSchema.methods.toSafeJSON = function () {
  const obj = this.toObject();
  delete obj.passwordHash;
  delete obj.twoFactorSecret;
  delete obj.passwordHistory;
  delete obj.__v;
  return obj;
};

module.exports = mongoose.model('User', userSchema);
