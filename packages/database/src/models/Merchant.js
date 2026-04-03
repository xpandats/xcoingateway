'use strict';

const mongoose = require('mongoose');

const merchantSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  businessName: { type: String, required: true, trim: true },
  isActive: { type: Boolean, default: true, index: true },

  // API credentials
  apiKeys: [{
    keyId: { type: String, required: true },  // Public identifier (indexed via schema.index)
    keyHash: { type: String, required: true },  // Hashed API key (bcrypt)
    apiSecret: { type: String, required: true }, // Encrypted API secret (AES-256-GCM)
    label: { type: String, default: 'default' },
    permissions: [{ type: String }],
    isActive: { type: Boolean, default: true },
    lastUsedAt: { type: Date, default: null },
    createdAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, default: null }, // null = no expiry
  }],

  // Webhook configuration
  webhookUrl: { type: String, default: '' },
  webhookSecret: { type: String, default: '' }, // Encrypted
  webhookEvents: [{ type: String }], // Which events to send

  // Withdrawal settings
  withdrawalAddress: { type: String, default: '' }, // TRC20 address
  withdrawalAddressVerified: { type: Boolean, default: false },
  autoWithdrawal: { type: Boolean, default: false },
  autoWithdrawalThreshold: { type: Number, default: 100 }, // USDT
  autoWithdrawalInterval: { type: String, default: 'daily' }, // daily, weekly, manual

  // Fee settings (admin-configurable per merchant)
  feePercentage: { type: Number, default: 1.0, min: 0, max: 100 }, // Platform fee %
  fixedFee: { type: Number, default: 0, min: 0 }, // Fixed fee per tx in USDT

  // IP whitelist for API access (optional)
  ipWhitelist: [{ type: String }],
  ipWhitelistEnabled: { type: Boolean, default: false },

  // Stats (cached, updated periodically)
  stats: {
    totalReceived: { type: Number, default: 0 },
    totalWithdrawn: { type: Number, default: 0 },
    totalInvoices: { type: Number, default: 0 },
    totalSuccessful: { type: Number, default: 0 },
  },
}, {
  timestamps: true,
  collection: 'merchants',
  strict: true, // L4: explicit — reject unknown fields at DB write level
});

merchantSchema.index({ businessName: 'text' });
merchantSchema.index({ 'apiKeys.keyId': 1 });

// B3: Enforce webhookSecret is encrypted before saving
// Prevents accidental storage of plaintext webhook secrets
merchantSchema.pre('save', function (next) {
  if (this.webhookSecret && this.webhookSecret.length > 0) {
    if (!this.webhookSecret.startsWith('v1:')) {
      return next(new Error('SECURITY: webhookSecret must be AES-256-GCM encrypted (v1: format) before saving'));
    }
  }
  next();
});

merchantSchema.methods.toSafeJSON = function () {
  const obj = this.toObject();
  if (obj.apiKeys) {
    obj.apiKeys = obj.apiKeys.map((k) => ({
      keyId: k.keyId,
      label: k.label,
      isActive: k.isActive,
      lastUsedAt: k.lastUsedAt,
      createdAt: k.createdAt,
    }));
  }
  delete obj.webhookSecret;
  delete obj.__v;
  return obj;
};

module.exports = mongoose.model('Merchant', merchantSchema);
