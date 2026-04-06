'use strict';

/**
 * @module models/EnergyStake
 *
 * Energy Stake — Tracks TRX staking/freezing for energy on Tron network.
 *
 * WHY THIS EXISTS (from Description.txt):
 *   "Freeze TRX in hot wallet to get daily free Energy"
 *   "Track energy balance before each withdrawal"
 *   "If insufficient energy → queue withdrawal, alert admin"
 *
 *   Without tracking:
 *     - No visibility into how much TRX is frozen
 *     - No history of energy received from staking
 *     - No audit trail when admin freezes/unfreezes TRX
 *     - No forecasting of energy needs vs capacity
 *
 * USAGE:
 *   - Admin freezes TRX → EnergyStake created (status: active)
 *   - TRX unfreezing period (14 days on Tron) → status: unstaking
 *   - TRX fully unfrozen → status: unstaked
 *   - Future: energy rental service integration
 */

const mongoose = require('mongoose');

const STAKE_STATUS = Object.freeze({
  ACTIVE:     'active',     // TRX is frozen, energy is being received
  UNSTAKING:  'unstaking',  // Unfreeze initiated, 14-day wait period
  UNSTAKED:   'unstaked',   // TRX fully unfrozen
  FAILED:     'failed',     // Freeze/unfreeze tx failed
});

const STAKE_TYPE = Object.freeze({
  FREEZE_SELF:     'freeze_self',      // Freeze own TRX for energy
  DELEGATE_TO:     'delegate_to',      // Delegate energy to another wallet
  RECEIVE_FROM:    'receive_from',     // Received delegated energy
  ENERGY_RENTAL:   'energy_rental',    // Rented energy from external service
});

const energyStakeSchema = new mongoose.Schema({
  stakeId: { type: String, required: true, unique: true },  // stk_xxx

  // Wallet
  walletId:      { type: mongoose.Schema.Types.ObjectId, ref: 'Wallet', required: true, index: true },
  walletAddress: { type: String, required: true, index: true },
  network:       { type: String, default: 'tron' },

  // Stake type
  stakeType: {
    type: String,
    enum: Object.values(STAKE_TYPE),
    required: true,
    index: true,
  },

  // Amount
  trxAmount:      { type: Number, required: true, min: 0 },       // TRX frozen
  energyReceived: { type: Number, default: 0 },                   // Energy per day from this stake
  bandwidthReceived: { type: Number, default: 0 },                 // Bandwidth per day

  // Delegation (if type is delegate_to or receive_from)
  delegateToAddress:   { type: String, default: null },
  delegateFromAddress: { type: String, default: null },

  // Blockchain
  freezeTxHash:    { type: String, default: null, index: true },
  unfreezeTxHash:  { type: String, default: null },
  frozenAt:        { type: Date, default: null },
  unfreezeStartAt: { type: Date, default: null },            // When unfreeze was initiated
  unfreezeReadyAt: { type: Date, default: null },            // When TRX can be withdrawn (14 days)
  unstakedAt:      { type: Date, default: null },

  // Status
  status: {
    type: String,
    enum: Object.values(STAKE_STATUS),
    default: STAKE_STATUS.ACTIVE,
    index: true,
  },

  // Cost tracking (for energy rental)
  rentalCostUsdt:     { type: Number, default: null },
  rentalDurationHrs:  { type: Number, default: null },
  rentalProvider:     { type: String, default: null },

  // Audit
  initiatedBy: { type: String, required: true },  // userId or 'system'
  notes:       { type: String, default: '' },
}, {
  timestamps: true,
  collection: 'energy_stakes',
  strict: true,
});

// Indexes
energyStakeSchema.index({ walletId: 1, status: 1 });
energyStakeSchema.index({ stakeType: 1, status: 1, createdAt: -1 });
energyStakeSchema.index({ status: 1, unfreezeReadyAt: 1 }); // For checking when TRX can be withdrawn

module.exports = mongoose.model('EnergyStake', energyStakeSchema);
module.exports.STAKE_STATUS = STAKE_STATUS;
module.exports.STAKE_TYPE   = STAKE_TYPE;
