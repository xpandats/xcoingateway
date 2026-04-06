# ============================================================
# XCOINGATEWAY — PRODUCTION DOCKERFILE
# ============================================================
#
# Multi-stage build:
#   Stage 1 (deps):  Install production dependencies only
#   Stage 2 (app):   Copy source + deps, set non-root user
#
# SECURITY:
#   - Runs as non-root user (xcg:xcg, UID 1001)
#   - Uses alpine for minimal attack surface
#   - npm ci with --omit=dev (no devDependencies in image)
#   - .dockerignore excludes .env, .git, tests, node_modules
#
# BUILD:
#   docker build -t xcg-app .
#
# Each service uses the SAME image but different CMD:
#   docker-compose.yml specifies `command: ["node", "services/<svc>/src/server.js"]`
#   Default CMD runs the api-server.
# ============================================================

# ── Stage 1: Install dependencies ───────────────────────────────────────────

FROM node:20-alpine AS deps

WORKDIR /app

# Copy workspace root + all package.json files first (layer cache optimization)
COPY package.json package-lock.json ./
COPY packages/common/package.json packages/common/
COPY packages/cache/package.json packages/cache/
COPY packages/crypto/package.json packages/crypto/
COPY packages/database/package.json packages/database/
COPY packages/logger/package.json packages/logger/
COPY packages/queue/package.json packages/queue/
COPY packages/tron/package.json packages/tron/
COPY services/api-server/package.json services/api-server/
COPY services/blockchain-listener/package.json services/blockchain-listener/
COPY services/matching-engine/package.json services/matching-engine/
COPY services/withdrawal-engine/package.json services/withdrawal-engine/
COPY services/notification-service/package.json services/notification-service/
COPY services/reconciliation-service/package.json services/reconciliation-service/
COPY services/signing-service/package.json services/signing-service/

# Install production-only dependencies (no devDependencies, no tests)
RUN npm ci --omit=dev --ignore-scripts

# ── Stage 2: Copy source + run ──────────────────────────────────────────────

FROM node:20-alpine AS app

# Security: create non-root user
RUN addgroup -g 1001 -S xcg && \
    adduser -u 1001 -S xcg -G xcg

WORKDIR /app

# Copy node_modules from deps stage
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/packages/*/node_modules ./packages/

# Copy source (respect .dockerignore)
COPY packages/ packages/
COPY services/ services/
COPY package.json ./

# Create log directory (PM2/Docker logs)
RUN mkdir -p /var/log/xcg && chown -R xcg:xcg /var/log/xcg

# Set ownership to non-root user
RUN chown -R xcg:xcg /app

# Switch to non-root user
USER xcg

# Expose health check ports (services use 3090-3097)
# The actual app port is 3000 (api-server)
EXPOSE 3000 3090 3091 3092 3093 3094 3095 3096 3097

# Default: api-server (overridden per-service in docker-compose.yml)
CMD ["node", "services/api-server/src/server.js"]
