'use strict';

/**
 * PM2 Ecosystem Config — XCoinGateway Production.
 *
 * SECURITY ZONES:
 *   Zone 2 — Application: api-server, blockchain-listener, matching-engine,
 *                          withdrawal-engine, notification-service, reconciliation-service
 *   Zone 3 — Secure Vault: signing-service (separate OS user in production)
 *
 * USAGE:
 *   pm2 start ecosystem.config.js --env production
 *   pm2 start ecosystem.config.js --env staging
 *   pm2 save       (persist process list across reboots)
 *   pm2 startup    (generate OS-level startup script)
 *   pm2 monit      (live dashboard)
 *   pm2 logs xcg-api-server --lines 200
 *
 * LOG DIR: Create before first run
 *   mkdir -p /var/log/xcg && chown xcg:xcg /var/log/xcg
 */

module.exports = {
  apps: [

    // ─── 1. API Server (Zone 2 — Public-Facing) ─────────────────────────────
    {
      name:               'xcg-api-server',
      script:             './services/api-server/src/server.js',
      instances:          'max',        // 1 per CPU — cluster mode
      exec_mode:          'cluster',
      autorestart:        true,
      max_restarts:       10,
      min_uptime:         '10s',
      restart_delay:      3000,
      max_memory_restart: '512M',
      watch:              false,
      kill_timeout:       35000,        // 35s — must be > shutdown.js FORCE_KILL_TIMEOUT_MS (30s)
      error_file:         '/var/log/xcg/api-server.err.log',
      out_file:           '/var/log/xcg/api-server.out.log',
      merge_logs:         true,
      log_date_format:    'YYYY-MM-DD HH:mm:ss.SSS Z',
      env_production: {
        NODE_ENV:     'production',
        NETWORK_MODE: 'MAINNET',
        TRON_NETWORK: 'mainnet',
        PORT:         3000,
      },
      env_staging: {
        NODE_ENV:         'staging',
        NETWORK_MODE:     'TESTNET',
        TRON_NETWORK:     'testnet',
        TRONGRID_API_URL: 'https://nile.trongrid.io',
        PORT:             3001,
      },
    },

    // ─── 2. Blockchain Listener (Zone 2) ────────────────────────────────────
    // MUST be instances:1 — single polling loop prevents duplicate tx detection
    {
      name:               'xcg-blockchain-listener',
      script:             './services/blockchain-listener/src/server.js',
      instances:          1,
      exec_mode:          'fork',
      autorestart:        true,
      max_restarts:       10,
      min_uptime:         '15s',
      restart_delay:      5000,
      max_memory_restart: '256M',
      watch:              false,
      kill_timeout:       35000,        // 35s — must be > shutdown.js FORCE_KILL_TIMEOUT_MS (30s)
      error_file:         '/var/log/xcg/blockchain-listener.err.log',
      out_file:           '/var/log/xcg/blockchain-listener.out.log',
      merge_logs:         true,
      log_date_format:    'YYYY-MM-DD HH:mm:ss.SSS Z',
      env_production: { NODE_ENV: 'production', NETWORK_MODE: 'MAINNET', TRON_NETWORK: 'mainnet' },
      env_staging:    { NODE_ENV: 'staging',    NETWORK_MODE: 'TESTNET', TRON_NETWORK: 'testnet', TRONGRID_API_URL: 'https://nile.trongrid.io' },
    },

    // ─── 3. Matching Engine (Zone 2) ────────────────────────────────────────
    // MUST be instances:1 — atomicity requires single consumer for matching
    {
      name:               'xcg-matching-engine',
      script:             './services/matching-engine/src/server.js',
      instances:          1,
      exec_mode:          'fork',
      autorestart:        true,
      max_restarts:       10,
      min_uptime:         '10s',
      restart_delay:      3000,
      max_memory_restart: '256M',
      watch:              false,
      kill_timeout:       35000,        // 35s — must be > shutdown.js FORCE_KILL_TIMEOUT_MS (30s)
      error_file:         '/var/log/xcg/matching-engine.err.log',
      out_file:           '/var/log/xcg/matching-engine.out.log',
      merge_logs:         true,
      log_date_format:    'YYYY-MM-DD HH:mm:ss.SSS Z',
      env_production: { NODE_ENV: 'production', NETWORK_MODE: 'MAINNET', TRON_NETWORK: 'mainnet' },
      env_staging:    { NODE_ENV: 'staging',    NETWORK_MODE: 'TESTNET', TRON_NETWORK: 'testnet', TRONGRID_API_URL: 'https://nile.trongrid.io' },
    },

    // ─── 4. Withdrawal Engine (Zone 2) ──────────────────────────────────────
    {
      name:               'xcg-withdrawal-engine',
      script:             './services/withdrawal-engine/src/server.js',
      instances:          1,
      exec_mode:          'fork',
      autorestart:        true,
      max_restarts:       10,
      min_uptime:         '10s',
      restart_delay:      5000,
      max_memory_restart: '256M',
      watch:              false,
      kill_timeout:       35000,        // 35s — must be > shutdown.js FORCE_KILL_TIMEOUT_MS (30s)
      error_file:         '/var/log/xcg/withdrawal-engine.err.log',
      out_file:           '/var/log/xcg/withdrawal-engine.out.log',
      merge_logs:         true,
      log_date_format:    'YYYY-MM-DD HH:mm:ss.SSS Z',
      env_production: { NODE_ENV: 'production', NETWORK_MODE: 'MAINNET', TRON_NETWORK: 'mainnet' },
      env_staging:    { NODE_ENV: 'staging',    NETWORK_MODE: 'TESTNET', TRON_NETWORK: 'testnet', TRONGRID_API_URL: 'https://nile.trongrid.io' },
    },

    // ─── 5. Notification Service (Zone 2) ───────────────────────────────────
    {
      name:               'xcg-notification-service',
      script:             './services/notification-service/src/server.js',
      instances:          1,
      exec_mode:          'fork',
      autorestart:        true,
      max_restarts:       10,
      min_uptime:         '10s',
      restart_delay:      3000,
      max_memory_restart: '256M',
      watch:              false,
      kill_timeout:       35000,        // 35s — must be > shutdown.js FORCE_KILL_TIMEOUT_MS (30s)
      error_file:         '/var/log/xcg/notification-service.err.log',
      out_file:           '/var/log/xcg/notification-service.out.log',
      merge_logs:         true,
      log_date_format:    'YYYY-MM-DD HH:mm:ss.SSS Z',
      env_production: { NODE_ENV: 'production', NETWORK_MODE: 'MAINNET' },
      env_staging:    { NODE_ENV: 'staging',    NETWORK_MODE: 'TESTNET' },
    },

    // ─── 6. Signing Service (Zone 3 — MAXIMUM SECURITY) ─────────────────────
    // PRODUCTION:
    //   Run as a SEPARATE OS user with minimal permissions
    //   Firewall: only Redis port accessible (block all other outbound except TronGrid)
    //   5 max restarts — signing crashes = investigate before auto-restart
    {
      name:               'xcg-signing-service',
      script:             './services/signing-service/src/server.js',
      instances:          1,            // MUST be 1 in Zone 3
      exec_mode:          'fork',
      autorestart:        true,
      max_restarts:       5,            // Fewer — failures require investigation
      min_uptime:         '30s',
      restart_delay:      10000,
      max_memory_restart: '128M',
      watch:              false,
      kill_timeout:       30000,        // Longest — must complete any in-flight signing
      error_file:         '/var/log/xcg/signing-service.err.log',
      out_file:           '/var/log/xcg/signing-service.out.log',
      merge_logs:         true,
      log_date_format:    'YYYY-MM-DD HH:mm:ss.SSS Z',
      // MASTER_ENCRYPTION_KEY injected from system environment — NOT here
      env_production: { NODE_ENV: 'production', NETWORK_MODE: 'MAINNET', TRON_NETWORK: 'mainnet' },
      env_staging:    { NODE_ENV: 'staging',    NETWORK_MODE: 'TESTNET', TRON_NETWORK: 'testnet', TRONGRID_API_URL: 'https://nile.trongrid.io' },
    },

    // ─── 7. Reconciliation Service (Zone 2) ─────────────────────────────────
    // Runs every 15 minutes — NOT queue-based
    {
      name:               'xcg-reconciliation-service',
      script:             './services/reconciliation-service/src/server.js',
      instances:          1,
      exec_mode:          'fork',
      autorestart:        true,
      max_restarts:       5,
      min_uptime:         '30s',
      restart_delay:      60000,        // 60s on crash — reconciler should be rock-solid
      max_memory_restart: '256M',
      watch:              false,
      kill_timeout:       30000,
      error_file:         '/var/log/xcg/reconciliation-service.err.log',
      out_file:           '/var/log/xcg/reconciliation-service.out.log',
      merge_logs:         true,
      log_date_format:    'YYYY-MM-DD HH:mm:ss.SSS Z',
      env_production: { NODE_ENV: 'production', NETWORK_MODE: 'MAINNET', TRON_NETWORK: 'mainnet' },
      env_staging:    { NODE_ENV: 'staging',    NETWORK_MODE: 'TESTNET', TRON_NETWORK: 'testnet', TRONGRID_API_URL: 'https://nile.trongrid.io' },
    },

  ],

  // ─── pm2 deploy (optional — can also use CI/CD pipeline) ─────────────────
  deploy: {
    production: {
      user:          'xcg',
      host:          ['YOUR_PRODUCTION_SERVER_IP'],
      ref:           'origin/master',
      repo:          'git@github.com:xpandats/xcoingateway.git',
      path:          '/home/xcg/app',
      'post-deploy': 'npm ci && pm2 reload ecosystem.config.js --env production && pm2 save',
    },
    staging: {
      user:          'xcg',
      host:          ['YOUR_STAGING_SERVER_IP'],
      ref:           'origin/develop',
      repo:          'git@github.com:xpandats/xcoingateway.git',
      path:          '/home/xcg/staging',
      'post-deploy': 'npm ci && pm2 reload ecosystem.config.js --env staging && pm2 save',
    },
  },
};
