'use strict';

/**
 * @module models/GasFeeRecord
 *
 * Gas Fee Record — Tracks TRX/energy costs for on-chain operations.
 *
 * WHY THIS EXISTS:
 *   Tron TRC20 transfers require Energy (from frozen TRX) or burn TRX as gas.
 *   Without tracking:
 *     - You can't audit operational costs
 *     - You can't detect wallets running low on TRX for gas
 *     - You can't forecast energy needs based on transaction volume
 *     - You can't reconcile TRX spending against actual transactions
 *
 * IMMUTABLE: Gas records are financial evidence — no updates or deletes.
 *
 * USAGE:
 *   Created automatically by withdrawal-engine and signing-service after
 *   every on-chain broadcast (withdrawal, refund, or internal transfer).
 */

const mongoose = require('mongoose');

const GAS_OPERATION_TYPE = Object.freeze({
  WITHDRAWAL:      'withdrawal',       // Merchant payout
  REFUND:          'refund',           // Customer refund
  SWEEP:           'sweep',            // Hot → cold wallet sweep
  INTERNAL:        'internal',         // Internal wallet-to-wallet transfer
  ENERGY_DELEGATE: 'energy_delegate',  // Energy delegation transaction
  GAS_TOPUP:       'gas_topup',        // TRX top-up to receiving wallet
});

const gasFeeRecordSchema = new mongoose.Schema({
  recordId: { type: String, required: true, unique: true },  // gas_xxx

  // Operation context
  operationType: {
    type: String,
    enum: Object.values(GAS_OPERATION_TYPE),
    required: true,
    index: true,
  },

  // Source references
  withdrawalId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Withdrawal', default: null, index: true },
  refundId:      { type: mongoose.Schema.Types.ObjectId, ref: 'Refund', default: null },
  walletId:      { type: mongoose.Schema.Types.ObjectId, ref: 'Wallet', default: null, index: true },
  walletAddress: { type: String, required: true, index: true },
  network:       { type: String, default: 'tron' },

  // Gas costs
  gasUsed:        { type: Number, required: true, min: 0 },   // TRX burned as gas
  energyUsed:     { type: Number, default: 0 },               // Energy consumed (free from staking)
  bandwidthUsed:  { type: Number, default: 0 },               // Bandwidth consumed
  energyAvailableBefore: { type: Number, default: null },      // Snapshot before tx
  energyAvailableAfter:  { type: Number, default: null },      // Snapshot after tx

  // TRX balance tracking
  trxBalanceBefore: { type: Number, default: null },
  trxBalanceAfter:  { type: Number, default: null },

  // USD equivalent (for cost reporting)
  gasUsdEquivalent: { type: Number, default: null },  // Approximate USD cost

  // Blockchain
  txHash: { type: String, required: true, index: true },

  // Alerts
  lowTrxAlert:     { type: Boolean, default: false },  // True if trxBalanceAfter < threshold
  lowEnergyAlert:  { type: Boolean, default: false },  // True if energy critically low
}, {
  timestamps: true,
  collection: 'gas_fee_records',
  strict: true,
});

// Performance indexes
gasFeeRecordSchema.index({ walletAddress: 1, createdAt: -1 });
gasFeeRecordSchema.index({ operationType: 1, createdAt: -1 });
gasFeeRecordSchema.index({ lowTrxAlert: 1, createdAt: -1 });

// Immutability — gas records are financial evidence
function immutableError(next) {
  next(new Error('SECURITY: GasFeeRecord is immutable — no updates/deletes allowed'));
}
gasFeeRecordSchema.pre('updateOne',         function (next) { immutableError(next); });
gasFeeRecordSchema.pre('updateMany',        function (next) { immutableError(next); });
gasFeeRecordSchema.pre('findOneAndUpdate',  function (next) { immutableError(next); });
gasFeeRecordSchema.pre('deleteOne',         function (next) { immutableError(next); });
gasFeeRecordSchema.pre('deleteMany',        function (next) { immutableError(next); });
gasFeeRecordSchema.pre('findOneAndDelete',  function (next) { immutableError(next); });
gasFeeRecordSchema.pre('findOneAndReplace', function (next) { immutableError(next); });

gasFeeRecordSchema.pre('save', function (next) {
  if (!this.isNew) return immutableError(next);
  next();
});

module.exports = mongoose.model('GasFeeRecord', gasFeeRecordSchema);
module.exports.GAS_OPERATION_TYPE = GAS_OPERATION_TYPE;
