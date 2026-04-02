'use strict';

const mongoose = require('mongoose');
const { ROLES } = require('@xcg/common').constants;

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
  passwordHash: { type: String, required: true },
  firstName: { type: String, required: true, trim: true },
  lastName: { type: String, required: true, trim: true },
  role: { type: String, enum: Object.values(ROLES), required: true, index: true },
  isActive: { type: Boolean, default: true, index: true },

  // 2FA
  twoFactorSecret: { type: String, default: null }, // Encrypted TOTP secret
  twoFactorEnabled: { type: Boolean, default: false },

  // Security
  failedLoginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date, default: null },
  lastLoginAt: { type: Date, default: null },
  lastLoginIp: { type: String, default: null },
  passwordChangedAt: { type: Date, default: null },

  // Refresh tokens (array for multi-device support)
  refreshTokens: [{
    tokenHash: { type: String, required: true },
    ip: { type: String },
    userAgent: { type: String },
    createdAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, required: true },
  }],

  // Merchant reference (if role is merchant)
  merchantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant', default: null },
}, {
  timestamps: true,
  collection: 'users',
});

// Indexes
userSchema.index({ email: 1, isActive: 1 });
userSchema.index({ role: 1, isActive: 1 });
userSchema.index({ 'refreshTokens.tokenHash': 1 });

// Virtual: is account locked?
userSchema.virtual('isLocked').get(function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// NEVER return sensitive fields in JSON
userSchema.methods.toSafeJSON = function () {
  const obj = this.toObject();
  delete obj.passwordHash;
  delete obj.twoFactorSecret;
  delete obj.refreshTokens;
  delete obj.__v;
  return obj;
};

module.exports = mongoose.model('User', userSchema);
