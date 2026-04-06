'use strict';

/**
 * @module models/WalletAssignment
 *
 * Wallet Assignment — Tracks which wallet is assigned to which invoice/merchant.
 *
 * WHY THIS EXISTS (from Description.txt):
 *   "Admin adds wallet addresses via admin panel"
 *   "Each wallet address is assigned to receive payments"
 *   "Multiple wallets possible for load distribution"
 *   "Wallet rotation to avoid single point of failure"
 *
 *   Without tracking:
 *     - No history of which wallet received which payment
 *     - Cannot trace fund flow when wallet is decommissioned
 *     - No load balancing metrics (how many invoices per wallet?)
 *     - Cannot audit wallet utilization patterns
 *
 * ASSIGNMENT FLOW:
 *   1. New invoice created → system selects best wallet (lowest active invoices, below balance threshold)
 *   2. WalletAssignment created linking invoice → wallet
 *   3. After invoice confirmed → assignment status = completed
 *   4. After invoice expired → assignment status = expired (wallet slot freed)
 */

const mongoose = require('mongoose');

const ASSIGNMENT_STATUS = Object.freeze({
  ACTIVE:    'active',      // Wallet is currently assigned to this invoice
  COMPLETED: 'completed',   // Payment received and confirmed
  EXPIRED:   'expired',     // Invoice expired, wallet slot freed
  CANCELLED: 'cancelled',   // Invoice cancelled
});

const walletAssignmentSchema = new mongoose.Schema({
  // Links
  walletId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Wallet', required: true, index: true },
  invoiceId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Invoice', required: true, index: true },
  merchantId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant', required: true, index: true },

  // Address snapshot (in case wallet is later renamed or deleted)
  walletAddress: { type: String, required: true },
  network:       { type: String, default: 'tron' },

  // Status
  status: {
    type: String,
    enum: Object.values(ASSIGNMENT_STATUS),
    default: ASSIGNMENT_STATUS.ACTIVE,
    index: true,
  },

  // Timing
  assignedAt: { type: Date, default: Date.now },
  expiresAt:  { type: Date, required: true, index: true },  // Same as invoice expiry
  releasedAt: { type: Date, default: null },

  // Selection metadata (for load balancing analysis)
  selectionReason: { type: String, default: null },  // 'lowest_active_count', 'round_robin', etc.
  activeCountAtAssignment: { type: Number, default: null }, // How many active invoices wallet had
  balanceAtAssignment:     { type: Number, default: null }, // Wallet USDT balance at assignment
}, {
  timestamps: true,
  collection: 'wallet_assignments',
  strict: true,
});

// Performance indexes
walletAssignmentSchema.index({ walletId: 1, status: 1 });
walletAssignmentSchema.index({ walletId: 1, status: 1, expiresAt: 1 });
walletAssignmentSchema.index({ status: 1, expiresAt: 1 }); // For expired assignment cleanup
walletAssignmentSchema.index({ merchantId: 1, createdAt: -1 });

/**
 * Count active assignments for a wallet.
 * Used by wallet selection logic to find least-loaded wallet.
 */
walletAssignmentSchema.statics.getActiveCountForWallet = async function (walletId) {
  return this.countDocuments({
    walletId,
    status: ASSIGNMENT_STATUS.ACTIVE,
    expiresAt: { $gt: new Date() },
  });
};

module.exports = mongoose.model('WalletAssignment', walletAssignmentSchema);
module.exports.ASSIGNMENT_STATUS = ASSIGNMENT_STATUS;
