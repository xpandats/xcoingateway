'use strict';

/**
 * @module models/WalletTransfer
 *
 * Wallet Transfer — Internal fund movements between our own wallets.
 *
 * WHY THIS EXISTS:
 *   - Hot → Cold sweep: when hot wallet exceeds maxBalance threshold
 *   - Cold → Hot replenishment: when hot wallet runs low for withdrawal processing
 *   - Gas top-up: sending TRX to receiving wallets for energy
 *   - Wallet rotation: moving funds when decommissioning a wallet
 *
 *   Without tracking: fund movements between our own wallets are invisible
 *   to reconciliation, creating unexplained balance mismatches.
 *
 * IMMUTABLE: Internal transfers are financial records.
 */

const mongoose = require('mongoose');

const TRANSFER_TYPE = Object.freeze({
  HOT_TO_COLD:    'hot_to_cold',       // Auto-sweep excess funds to cold storage
  COLD_TO_HOT:    'cold_to_hot',       // Replenish hot wallet (admin-triggered)
  GAS_TOPUP:      'gas_topup',         // TRX top-up for energy
  WALLET_RETIRE:  'wallet_retire',     // Drain before decommissioning wallet
  CONSOLIDATION:  'consolidation',     // Merge receiving wallet balances
});

const TRANSFER_STATUS = Object.freeze({
  PENDING:     'pending',
  SIGNING:     'signing',
  BROADCAST:   'broadcast',
  CONFIRMING:  'confirming',
  COMPLETED:   'completed',
  FAILED:      'failed',
  CANCELLED:   'cancelled',
});

const walletTransferSchema = new mongoose.Schema({
  transferId: { type: String, required: true, unique: true },  // trf_xxx

  // Source wallet
  fromWalletId: { type: mongoose.Schema.Types.ObjectId, ref: 'Wallet', required: true, index: true },
  fromAddress:  { type: String, required: true },

  // Destination wallet
  toWalletId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Wallet', required: true, index: true },
  toAddress:    { type: String, required: true },

  // Transfer type
  transferType: {
    type: String,
    enum: Object.values(TRANSFER_TYPE),
    required: true,
    index: true,
  },

  // Amounts
  amount:     { type: Number, required: true, min: 0.000001 },
  token:      { type: String, default: 'USDT' },   // 'USDT' or 'TRX'
  network:    { type: String, default: 'tron' },

  // Status
  status: {
    type: String,
    enum: Object.values(TRANSFER_STATUS),
    default: TRANSFER_STATUS.PENDING,
    index: true,
  },

  // Blockchain
  txHash:         { type: String, default: null, index: true },
  confirmations:  { type: Number, default: 0 },
  broadcastAt:    { type: Date, default: null },
  confirmedAt:    { type: Date, default: null },

  // Gas cost tracking
  gasFeeRecordId: { type: mongoose.Schema.Types.ObjectId, ref: 'GasFeeRecord', default: null },

  // Ledger
  ledgerEntryIds: [{ type: String }],  // LedgerEntry references for double-entry

  // Processing
  attempts:  { type: Number, default: 0 },
  lastError: { type: String, default: null },

  // Audit
  triggeredBy: { type: String, required: true },  // 'system' | 'admin:userId'
  reason:      { type: String, default: '' },      // Why this transfer happened
  approvedBy:  { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
}, {
  timestamps: true,
  collection: 'wallet_transfers',
  strict: true,
});

// Indexes
walletTransferSchema.index({ fromWalletId: 1, createdAt: -1 });
walletTransferSchema.index({ toWalletId: 1, createdAt: -1 });
walletTransferSchema.index({ transferType: 1, status: 1 });
walletTransferSchema.index({ status: 1, createdAt: -1 });

// Immutability — delete/replace blocked
function immutableError(next) {
  next(new Error('SECURITY: WalletTransfer records are immutable'));
}
walletTransferSchema.pre('deleteOne',         function (next) { immutableError(next); });
walletTransferSchema.pre('deleteMany',        function (next) { immutableError(next); });
walletTransferSchema.pre('findOneAndDelete',  function (next) { immutableError(next); });
walletTransferSchema.pre('findOneAndReplace', function (next) { immutableError(next); });

module.exports = mongoose.model('WalletTransfer', walletTransferSchema);
module.exports.TRANSFER_TYPE   = TRANSFER_TYPE;
module.exports.TRANSFER_STATUS = TRANSFER_STATUS;
