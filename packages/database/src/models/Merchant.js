'use strict';

const mongoose = require('mongoose');

const merchantSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  businessName: { type: String, required: true, trim: true },
  email: { type: String, default: '', trim: true, lowercase: true },  // Contact email
  isActive: { type: Boolean, default: true, index: true },

  // Approval workflow — merchants must be approved by admin before accepting payments
  isApproved:      { type: Boolean, default: false, index: true },
  approvalStatus:  { type: String, enum: ['pending', 'approved', 'rejected', 'suspended'], default: 'pending', index: true },
  approvedBy:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  approvedAt:      { type: Date, default: null },
  rejectedReason:  { type: String, default: '' },
  suspendedAt:     { type: Date, default: null },
  suspendedReason: { type: String, default: '' },
  suspendedBy:     { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },

  // Per-merchant rate limits (admin-configurable, overrides platform defaults)
  rateLimits: {
    invoicesPerMinute:     { type: Number, default: 20 },
    withdrawalsPerMinute:  { type: Number, default: 10 },
    readsPerMinute:        { type: Number, default: 100 },
  },

  // API credentials
  apiKeys: [{
    keyId:     { type: String, required: true },             // Public identifier
    // G7 FIX: select:false — these never appear in .lean() queries or explicit .find()
    keyHash:   { type: String, required: true, select: false },  // bcrypt hash
    apiSecret: { type: String, required: true, select: false },  // AES-256-GCM encrypted secret
    label:     { type: String, default: 'default' },
    permissions: [{ type: String }],
    isActive:  { type: Boolean, default: true },
    lastUsedAt:{ type: Date, default: null },
    createdAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, default: null },  // null = no expiry
  }],

  // Webhook configuration
  webhookUrl: { type: String, default: '' },
  webhookSecret: { type: String, default: '' }, // Encrypted
  webhookEvents: [{ type: String }], // Which events to send

  // Withdrawal settings
  withdrawalAddress: {
    type: String,
    default: '',
    validate: {
      validator: (v) => !v || /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(v),
      message: 'withdrawalAddress must be a valid TRC20 address (starts with T, 34 chars)',
    },
  }, // TRC20 address
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

  // Stats (periodically updated by background job, NOT used for financial decisions)
  // WARNING: Never use stats.* for balance/limit checks. Always use LedgerEntry.aggregate().
  // See: withdrawal-engine/src/processor.js _getDailyWithdrawalTotal() for the correct approach.
  stats: {
    totalReceived:   { type: Number, default: 0 },
    totalWithdrawn:  { type: Number, default: 0 },
    totalInvoices:   { type: Number, default: 0 },
    totalSuccessful: { type: Number, default: 0 },
  },
  // NOTE: NO cached dailyWithdrawalUsed field — that was a Gap-5 bug.
  // Daily withdrawal total is computed on-demand via LedgerEntry.aggregate() in the
  // withdrawal processor. Caching it here risks stale data causing wrong daily cap decisions.

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
