'use strict';

const mongoose = require('mongoose');
const { ROLES } = require('@xcg/common').constants;

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  firstName: { type: String, required: true, trim: true },
  lastName: { type: String, required: true, trim: true },
  role: { type: String, enum: Object.values(ROLES), required: true, index: true },
  isActive: { type: Boolean, default: true, index: true },

  // Admin approval (merchants require approval before they can operate)
  isApproved: { type: Boolean, default: false },
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  approvedAt: { type: Date, default: null },

  // 2FA
  twoFactorSecret: { type: String, default: null }, // Encrypted TOTP secret
  twoFactorEnabled: { type: Boolean, default: false },

  // Security
  failedLoginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date, default: null },
  lastLoginAt: { type: Date, default: null },
  lastLoginIp: { type: String, default: null },
  passwordChangedAt: { type: Date, default: null },

  // Password history (prevent reuse of last 5 passwords)
  passwordHistory: [{ type: String }], // Array of bcrypt hashes

  // Merchant reference (if role is merchant)
  merchantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant', default: null },
}, {
  timestamps: true,
  collection: 'users',
});

// Indexes
userSchema.index({ email: 1, isActive: 1 });
userSchema.index({ role: 1, isActive: 1 });

// Virtual: is account locked?
userSchema.virtual('isLocked').get(function () {
  if (!this.lockUntil) return false;
  if (this.lockUntil > Date.now()) return true;
  // Lock has expired — will be cleared on next login attempt
  return false;
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
