module.exports = {
  apps: [
    {
      name: 'xcg-api-server',
      script: 'services/api-server/src/server.js',
      instances: 'max',       // Cluster mode: one process per CPU core
      exec_mode: 'cluster',

      // INFRA-3: Memory limits — prevent single bad request from OOMing all workers
      max_memory_restart: '512M',

      // Restart policy
      autorestart: true,
      restart_delay: 3000,    // 3s delay between restarts (prevents restart loop DoS)
      max_restarts: 10,       // After 10 restarts, mark as errored (alert required)
      min_uptime: '10s',      // Must stay up 10s to count as successful restart

      // Logging
      error_file: 'logs/api-server-error.log',
      out_file: 'logs/api-server-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs: true,

      // Environment variables are NOT stored here — use .env files or Vault
      // NEVER add secrets to this file
      env: {
        NODE_ENV: 'production',
        PORT: 3001,
      },
      env_development: {
        NODE_ENV: 'development',
        PORT: 3001,
      },

      // Watch: disabled in production (use CI/CD for deployments)
      watch: false,

      // Kill timeout: grace period before SIGKILL
      kill_timeout: 5000,

      // Graceful reload: send SIGINT instead of SIGTERM (respects our shutdown handlers)
      listen_timeout: 10000,
      shutdown_with_message: false,

      // Source maps: disabled in production (don't expose internals)
      source_map_support: false,
    },
  ],
};
