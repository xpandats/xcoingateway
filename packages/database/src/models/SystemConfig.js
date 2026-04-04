'use strict';

/**
 * @module models/SystemConfig
 *
 * System Configuration — runtime-adjustable platform settings.
 *
 * SECURITY (G1 FIX):
 *   - Only whitelisted keys can be stored — rejects unknown config keys at schema pre-save
 *   - Value type is validated per key (prevents BSON injection via mixed type)
 *   - updatedBy is required — every change has an audit actor (G8 FIX)
 *   - updatedBy is tracked in AuditLog by systemController separately
 *
 * ALLOWED KEYS (maintain this list as the single source of truth):
 */

const mongoose = require('mongoose');

// G1 FIX: Exhaustive whitelist of allowed configuration keys
// Adding a new config REQUIRES adding it here first — design is intentional
const ALLOWED_CONFIG_KEYS = new Set([
  // Platform fee rate applied to all invoices unless overridden per merchant
  'platform.feeRate',
  // Maximum invoice amount in USDT
  'invoice.maxAmountUsdt',
  // Minimum invoice amount in USDT
  'invoice.minAmountUsdt',
  // Invoice expiry in seconds (default 3600 = 1 hour)
  'invoice.expirySeconds',
  // Amount offset precision (decimal places for uniqueness)
  'invoice.offsetPrecision',
  // Maximum number of active wallets to rotate between
  'wallet.maxActiveWallets',
  // Minimum TRX balance before wallet is flagged for top-up
  'wallet.minTrxReserve',
  // Withdrawal fee in USDT
  'withdrawal.feeUsdt',
  // Auto-approval threshold (above this = manual review required)
  'withdrawal.autoApproveMaxUsdt',
  // Blockchain confirmations required before invoice marked confirmed
  'blockchain.requiredConfirmations',
  // Polling interval for TronGrid in ms
  'blockchain.pollIntervalMs',
  // Max retries for webhook delivery
  'webhook.maxRetries',
  // Webhook retry backoff base in seconds
  'webhook.backoffBaseSeconds',
  // Risk score threshold to auto-block a transaction
  'fraud.autoBlockRiskScore',
  // Velocity limit: max invoices per merchant per minute
  'fraud.velocityMaxInvoicesPerMinute',
  // Whether the platform is in maintenance mode (bool)
  'platform.maintenanceMode',
]);

const systemConfigSchema = new mongoose.Schema({
  key: {
    type:     String,
    required: true,
    unique:   true,
    index:    true,
    trim:     true,
    validate: {
      validator: (v) => ALLOWED_CONFIG_KEYS.has(v),
      message: (props) => `'${props.value}' is not an allowed system config key. Add it to ALLOWED_CONFIG_KEYS first.`,
    },
  },
  value: {
    type:     mongoose.Schema.Types.Mixed,
    required: true,
  },
  description: { type: String, default: '' },
  // G8 FIX: updatedBy is required — every config change must record the admin actor
  updatedBy: {
    type:     mongoose.Schema.Types.ObjectId,
    ref:      'User',
    required: true,
  },
}, {
  timestamps: true,
  collection: 'system_config',
  strict:     true,
});

// G1 FIX: Pre-save validation — reject dangerous value types
systemConfigSchema.pre('save', function (next) {
  // Prevent MongoDB operator injection via Mixed type
  if (this.value !== null && typeof this.value === 'object') {
    const keys = Object.keys(this.value);
    if (keys.some((k) => k.startsWith('$'))) {
      return next(new Error('SECURITY: SystemConfig value cannot contain MongoDB operators'));
    }
  }
  next();
});

module.exports = mongoose.model('SystemConfig', systemConfigSchema);
module.exports.ALLOWED_CONFIG_KEYS = ALLOWED_CONFIG_KEYS;
