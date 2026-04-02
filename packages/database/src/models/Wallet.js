'use strict';

const mongoose = require('mongoose');

const walletSchema = new mongoose.Schema({
  address: { type: String, required: true, unique: true, index: true },
  network: { type: String, required: true, default: 'tron', index: true },
  encryptedPrivateKey: { type: String, required: true }, // AES-256-GCM encrypted
  label: { type: String, default: '' },
  isActive: { type: Boolean, default: true, index: true },
  type: { type: String, enum: ['hot', 'cold', 'receiving'], default: 'receiving', index: true },

  // Balance tracking (cached, verified by reconciliation)
  balance: {
    usdt: { type: Number, default: 0 },
    native: { type: Number, default: 0 }, // TRX for energy/bandwidth
    lastUpdated: { type: Date, default: null },
  },

  // Energy tracking (Tron-specific)
  energy: {
    available: { type: Number, default: 0 },
    total: { type: Number, default: 0 },
    lastUpdated: { type: Date, default: null },
  },

  // Usage tracking
  totalReceived: { type: Number, default: 0 },
  totalSent: { type: Number, default: 0 },
  transactionCount: { type: Number, default: 0 },
  lastActivityAt: { type: Date, default: null },

  // Thresholds
  maxBalance: { type: Number, default: 500 }, // Auto-sweep to cold wallet above this
  minNativeBalance: { type: Number, default: 10 }, // Alert if TRX below this

  // Admin
  addedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  disabledAt: { type: Date, default: null },
  disabledReason: { type: String, default: '' },
}, {
  timestamps: true,
  collection: 'wallets',
});

walletSchema.index({ network: 1, isActive: 1, type: 1 });
walletSchema.index({ 'balance.usdt': 1 });

// NEVER expose encrypted private key in JSON
walletSchema.methods.toSafeJSON = function () {
  const obj = this.toObject();
  delete obj.encryptedPrivateKey;
  delete obj.__v;
  return obj;
};

module.exports = mongoose.model('Wallet', walletSchema);
