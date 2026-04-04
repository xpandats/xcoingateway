'use strict';

/**
 * @module models/Wallet
 *
 * Wallet — Encrypted private key storage.
 *
 * BANK-GRADE REQUIREMENTS:
 *   - Private key encrypted with AES-256-GCM (per-wallet derived key)
 *   - Each wallet has unique random HKDF salt (not shared)
 *   - Private key NEVER exposed in JSON serialization
 *   - Balance tracking with reconciliation verification
 */

const mongoose = require('mongoose');

const walletSchema = new mongoose.Schema({
  address: { type: String, required: true, unique: true },
  network: { type: String, required: true, default: 'tron', index: true },
  encryptedPrivateKey: { type: String, required: true },
  label: { type: String, default: '' },
  isActive: { type: Boolean, default: true, index: true },
  type: { type: String, enum: ['hot', 'cold', 'receiving'], default: 'receiving', index: true },

  // SECURITY: Random salt for HKDF key derivation.
  // Each wallet uses a unique derived key = cryptographic isolation.
  derivationSalt: { type: String, required: true },

  // Balance tracking (cached, verified by reconciliation)
  balance: {
    usdt: { type: Number, default: 0 },
    native: { type: Number, default: 0 },
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
  maxBalance: { type: Number, default: 500 },
  minNativeBalance: { type: Number, default: 10 },

  // Admin
  addedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  disabledAt: { type: Date, default: null },
  disabledReason: { type: String, default: '' },
}, {
  timestamps: true,
  collection: 'wallets',
  strict: true,  // G2 FIX: Explicit — highest security model, never accept unknown fields
});

walletSchema.index({ network: 1, isActive: 1, type: 1 });
walletSchema.index({ 'balance.usdt': 1 });

// NEVER expose sensitive fields in JSON
walletSchema.methods.toSafeJSON = function () {
  const obj = this.toObject();
  delete obj.encryptedPrivateKey;
  delete obj.derivationSalt;
  delete obj.__v;
  return obj;
};

/**
 * K2: Atomic balance increment using MongoDB $inc.
 *
 * WHY: Read-modify-write (read balance → balance += amount → save) is NOT atomic.
 * Two concurrent transactions would cause balance drift (lost update problem).
 * $inc is the ONLY correct way to update wallet balances.
 *
 * USAGE (in wallet/transaction service):
 *   await Wallet.incrementBalance(walletId, { usdt: 150.5 });   // credit
 *   await Wallet.incrementBalance(walletId, { usdt: -150.5 });  // debit
 *
 * @param {string|ObjectId} walletId
 * @param {{ usdt?: number, native?: number }} delta - Amounts to add (negative for debit)
 * @param {mongoose.ClientSession} [session] - Optional transaction session
 * @returns {Promise<Document>} Updated wallet document
 */
walletSchema.statics.incrementBalance = async function (walletId, delta, session = null) {
  const inc = {};
  if (typeof delta.usdt === 'number') inc['balance.usdt'] = delta.usdt;
  if (typeof delta.native === 'number') inc['balance.native'] = delta.native;

  if (Object.keys(inc).length === 0) {
    throw new Error('incrementBalance: at least one balance field (usdt, native) must be provided');
  }

  const opts = { new: true };
  if (session) opts.session = session;

  return this.findByIdAndUpdate(
    walletId,
    {
      $inc: inc,
      $set: { 'balance.lastUpdated': new Date() },
    },
    opts,
  );
};

module.exports = mongoose.model('Wallet', walletSchema);
