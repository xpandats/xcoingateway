'use strict';

/**
 * Configuration Loader.
 *
 * Validates ALL required environment variables on startup.
 * If any critical config is missing, the server WILL NOT START.
 * This prevents silent failures in production.
 */

const path = require('path');
const { AppError } = require('@xcg/common');

// Load .env file for local development
const envFile = process.env.NODE_ENV === 'production'
  ? '.env.production'
  : process.env.NODE_ENV === 'staging'
    ? '.env.staging'
    : '.env.local';

require('dotenv').config({ path: path.resolve(process.cwd(), envFile) });
// Also try root .env as fallback
require('dotenv').config({ path: path.resolve(__dirname, '../../../', envFile) });
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env.local') });

/**
 * Validated configuration object.
 * Every value is validated and typed correctly.
 */
const config = {
  env: process.env.NODE_ENV || 'development',
  networkMode: process.env.NETWORK_MODE || 'TESTNET',
  port: parseInt(process.env.PORT, 10) || 3001,

  db: {
    uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/xcoingateway_dev',
  },

  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379',
  },

  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET,
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    accessExpiry: process.env.JWT_ACCESS_EXPIRY || '15m',
    refreshExpiry: process.env.JWT_REFRESH_EXPIRY || '7d',
  },

  encryption: {
    masterKey: process.env.MASTER_ENCRYPTION_KEY,
  },

  hmac: {
    secret: process.env.HMAC_SECRET,
    internalSecret: process.env.INTERNAL_HMAC_SECRET,
  },

  bcrypt: {
    saltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 12,
  },

  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 900000,
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 100,
    authMax: parseInt(process.env.AUTH_RATE_LIMIT_MAX, 10) || 5,
    authLockoutMs: parseInt(process.env.AUTH_LOCKOUT_DURATION_MS, 10) || 900000,
  },

  admin: {
    ipWhitelist: (process.env.ADMIN_IP_WHITELIST || '127.0.0.1,::1').split(',').map((s) => s.trim()),
    require2FA: process.env.ADMIN_2FA_REQUIRED === 'true',
  },

  wallet: {
    hotWalletMaxBalance: parseFloat(process.env.HOT_WALLET_MAX_BALANCE) || 500,
    coldWalletAddress: process.env.COLD_WALLET_ADDRESS || '',
    withdrawalCooldownMs: parseInt(process.env.WITHDRAWAL_COOLDOWN_MS, 10) || 60000,
    highValueThreshold: parseFloat(process.env.HIGH_VALUE_THRESHOLD) || 1000,
  },

  invoice: {
    expiryMs: parseInt(process.env.INVOICE_EXPIRY_MS, 10) || 1800000,
    minOffset: parseFloat(process.env.UNIQUE_AMOUNT_MIN_OFFSET) || 0.000001,
    maxOffset: parseFloat(process.env.UNIQUE_AMOUNT_MAX_OFFSET) || 0.009999,
  },

  tron: {
    apiUrl: process.env.TRONGRID_API_URL || 'https://api.shasta.trongrid.io',
    apiKey: process.env.TRONGRID_API_KEY || '',
    rpcFallback: process.env.TRON_RPC_FALLBACK || '',
    usdtContract: process.env.TRON_USDT_CONTRACT || 'TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs',
    confirmationsRequired: parseInt(process.env.TRON_CONFIRMATIONS_REQUIRED, 10) || 19,
    pollIntervalMs: parseInt(process.env.TRON_POLL_INTERVAL_MS, 10) || 5000,
  },
};

/**
 * Validate critical configuration on startup.
 * Server must NOT start if any critical config is missing.
 */
function validateConfig() {
  const errors = [];

  // J3: Minimum entropy check — secrets must be >= 64 hex chars (256-bit)
  const HEX_64 = /^[a-f0-9]{64}$/i;

  if (!config.jwt.accessSecret || config.jwt.accessSecret.includes('CHANGE_ME')) {
    errors.push('JWT_ACCESS_SECRET is not set or still has placeholder value');
  } else if (!HEX_64.test(config.jwt.accessSecret)) {
    errors.push('JWT_ACCESS_SECRET must be exactly 64 hex characters (256-bit minimum entropy)');
  }

  if (!config.jwt.refreshSecret || config.jwt.refreshSecret.includes('CHANGE_ME')) {
    errors.push('JWT_REFRESH_SECRET is not set or still has placeholder value');
  } else if (!HEX_64.test(config.jwt.refreshSecret)) {
    errors.push('JWT_REFRESH_SECRET must be exactly 64 hex characters (256-bit minimum entropy)');
  }

  if (!config.encryption.masterKey || config.encryption.masterKey.includes('CHANGE_ME')) {
    errors.push('MASTER_ENCRYPTION_KEY is not set or still has placeholder value');
  } else if (!HEX_64.test(config.encryption.masterKey)) {
    errors.push('MASTER_ENCRYPTION_KEY must be exactly 64 hex characters (256-bit minimum entropy)');
  }

  if (!config.hmac.secret || config.hmac.secret.includes('CHANGE_ME')) {
    errors.push('HMAC_SECRET is not set or still has placeholder value');
  } else if (!HEX_64.test(config.hmac.secret)) {
    errors.push('HMAC_SECRET must be exactly 64 hex characters (256-bit minimum entropy)');
  }

  if (config.env === 'production') {
    if (config.networkMode !== 'MAINNET') {
      errors.push('Production environment MUST use NETWORK_MODE=MAINNET');
    }

    // L1: MongoDB URI must have credentials in production
    if (config.db.uri.includes('localhost')) {
      errors.push('Production MUST NOT use localhost MongoDB');
    }
    if (!config.db.uri.includes('@')) {
      errors.push('Production MongoDB URI MUST include credentials (user:password@host)');
    }

    // L2: TLS must be enabled in production (checked via URI param or separate config)
    if (!config.db.uri.includes('tls=true') && !config.db.uri.includes('ssl=true')) {
      errors.push('Production MongoDB URI MUST enable TLS (add ?tls=true to URI)');
    }
  }

  if (errors.length > 0) {
    const msg = `Configuration validation failed:\n  - ${errors.join('\n  - ')}`;
    throw new Error(`FATAL: ${msg}`);
  }
}

module.exports = { config, validateConfig };
