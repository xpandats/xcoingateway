'use strict';

/**
 * PM2 Ecosystem Config — XCoinGateway Services
 *
 * SECURITY ZONES:
 *   Zone 2 — Application: api-server, blockchain-listener, matching-engine,
 *                          withdrawal-engine, notification-service, reconciliation-service
 *   Zone 3 — Secure Vault: signing-service (separate user in production)
 *
 * PRODUCTION NOTES:
 *   - signing-service MUST run as a separate OS user (e.g. xcg-signer)
 *   - signing-service MUST have NO network access except Redis port
 *   - All services should have resource limits set at OS level
 */

const BASE_ENV = {
  NODE_ENV: 'production',
  NETWORK_MODE: 'MAINNET',
};

module.exports = {
  apps: [
    // ─── Zone 2 Services ─────────────────────────────────────────────────────

    {
      name: 'xcg-api-server',
      script: './services/api-server/src/server.js',
      instances: 2,              // Horizontal scaling
      exec_mode: 'cluster',
      max_memory_restart: '512M',
      env: { ...BASE_ENV },
      env_development: { NODE_ENV: 'development', PORT: 3001 },
      error_file: './logs/api-server-error.log',
      out_file:   './logs/api-server-out.log',
    },

    {
      name: 'xcg-blockchain-listener',
      script: './services/blockchain-listener/src/server.js',
      instances: 1,              // MUST be 1 — single listener prevents duplicate detection
      max_memory_restart: '256M',
      env: { ...BASE_ENV },
      env_development: { NODE_ENV: 'development' },
      error_file: './logs/blockchain-listener-error.log',
      out_file:   './logs/blockchain-listener-out.log',
    },

    {
      name: 'xcg-matching-engine',
      script: './services/matching-engine/src/server.js',
      instances: 1,              // Single instance — atomic DB transactions prevent duplicate match
      max_memory_restart: '256M',
      env: { ...BASE_ENV },
      env_development: { NODE_ENV: 'development' },
      error_file: './logs/matching-engine-error.log',
      out_file:   './logs/matching-engine-out.log',
    },

    {
      name: 'xcg-withdrawal-engine',
      script: './services/withdrawal-engine/src/server.js',
      instances: 1,
      max_memory_restart: '256M',
      env: { ...BASE_ENV },
      env_development: { NODE_ENV: 'development' },
      error_file: './logs/withdrawal-engine-error.log',
      out_file:   './logs/withdrawal-engine-out.log',
    },

    {
      name: 'xcg-notification-service',
      script: './services/notification-service/src/server.js',
      instances: 1,
      max_memory_restart: '256M',
      env: { ...BASE_ENV },
      env_development: { NODE_ENV: 'development' },
      error_file: './logs/notification-service-error.log',
      out_file:   './logs/notification-service-out.log',
    },

    {
      name: 'xcg-reconciliation-service',
      script: './services/reconciliation-service/src/server.js',
      instances: 1,
      max_memory_restart: '256M',
      env: { ...BASE_ENV },
      env_development: { NODE_ENV: 'development' },
      error_file: './logs/reconciliation-service-error.log',
      out_file:   './logs/reconciliation-service-out.log',
    },

    // ─── Zone 3 — Secure Vault ───────────────────────────────────────────────
    // PRODUCTION: This process MUST run as a separate OS user with minimal permissions
    // The signing-service has NO HTTP endpoints — it only connects to Redis
    {
      name: 'xcg-signing-service',
      script: './services/signing-service/src/server.js',
      instances: 1,              // MUST be 1 — no parallel key operations
      max_memory_restart: '128M',
      env: { ...BASE_ENV },
      env_development: { NODE_ENV: 'development' },
      error_file: './logs/signing-service-error.log',
      out_file:   './logs/signing-service-out.log',
      // In production: pm2 start --uid xcg-signer --gid xcg-signer xcg-signing-service
    },
  ],
};
