'use strict';

/**
 * @module middleware/internalAuth
 *
 * Internal Service-to-Service Authentication Middleware.
 *
 * WHY THIS EXISTS (Gap C fix):
 *   XCoinGateway runs multiple services (api-server, withdrawal-engine, blockchain-listener,
 *   matching-engine, signing-service, notification-service). All share a MongoDB connection,
 *   but some services need to call API server internal endpoints:
 *     - Blockchain listener → API server: mark invoice as confirmed
 *     - Withdrawal engine  → API server: trigger notification
 *     - Notification svc   → API server: read webhook config
 *
 *   Without service identity verification, if any service is compromised, the attacker
 *   can call internal API endpoints freely — bypassing merchant auth and admin RBAC entirely.
 *
 * DESIGN — Shared Secret + HMAC (NOT mTLS for MVP):
 *   mTLS requires PKI infrastructure (CA certificates, cert rotation) which is complex
 *   to run on a zero-budget MVP. We use a simpler but still strong mechanism:
 *
 *   Each request from an internal service includes:
 *     X-Internal-Service: {service-name}   // Who is calling (e.g. "blockchain-listener")
 *     X-Internal-Timestamp: {unix-ms}      // When (±30s window prevents replay)
 *     X-Internal-Signature: {HMAC-SHA256}  // Proves ownership of INTERNAL_SERVICE_SECRET
 *
 *   Canonical string:
 *     INTERNAL:{service-name}:{timestamp}:{SHA256(body)}
 *
 *   The INTERNAL_SERVICE_SECRET is a shared key from env — different from JWT secrets.
 *   Future: replace with per-service secrets for finer-grained isolation.
 *
 * IMPORTANT RESTRICTIONS:
 *   - Internal endpoints are ONLY accessible from 127.0.0.1 / ::1 (loopback) or
 *     the configured INTERNAL_NETWORK_CIDR. An internet-exposed internal endpoint
 *     is NEVER acceptable, even with the HMAC in place.
 *   - Internal routes must NOT be mounted under public paths.
 *   - The shared secret has minimum 64 hex chars (256 bits) enforced at startup.
 *
 * USAGE:
 *   // In the internal router
 *   router.post('/internal/invoice/confirm', internalAuth, confirmInvoice);
 *
 *   // In a calling service (withdrawal-engine, etc.)
 *   const { signInternalRequest } = require('./utils/internalAuth');
 *   const headers = signInternalRequest('withdrawal-engine', body);
 *   await axios.post('http://api-server:3000/internal/...', body, { headers });
 */

const crypto = require('crypto');
const { AppError } = require('@xcg/common');
const { createLogger } = require('@xcg/logger');

const logger = createLogger('internal-auth');

const ALLOWED_SERVICES = new Set([
  'blockchain-listener',
  'withdrawal-engine',
  'matching-engine',
  'signing-service',
  'notification-service',
  'reconciliation-service',
]);

const TIMESTAMP_WINDOW_MS = 30_000; // ±30 seconds

/**
 * Get the internal service secret from environment.
 * Validated at first use (lazy) to avoid crashing on import if env not yet loaded.
 *
 * @returns {string} The secret
 */
function getInternalSecret() {
  const secret = process.env.INTERNAL_SERVICE_SECRET;
  if (!secret || secret.length < 64) {
    throw new Error(
      'FATAL: INTERNAL_SERVICE_SECRET must be at least 64 hex characters. ' +
      'Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
    );
  }
  return secret;
}

/**
 * Build the canonical string for HMAC signing.
 * Both client (calling service) and server (api-server) must produce identical output.
 *
 * @param {string} serviceName - Calling service identifier
 * @param {string} timestamp   - Unix milliseconds as string
 * @param {*} body             - Request body object (will be JSON.stringified)
 * @returns {string} Canonical string
 */
function buildInternalCanonical(serviceName, timestamp, body) {
  const bodyStr  = (body && typeof body === 'object' && Object.keys(body).length)
    ? JSON.stringify(body)
    : '';
  const bodyHash = crypto.createHash('sha256').update(bodyStr, 'utf8').digest('hex');
  return `INTERNAL:${serviceName}:${timestamp}:${bodyHash}`;
}

/**
 * Express middleware: validate internal service authentication.
 *
 * @param {object} req
 * @param {object} res
 * @param {Function} next
 */
async function internalAuth(req, res, next) {
  try {
    const serviceName = req.headers['x-internal-service'];
    const timestamp   = req.headers['x-internal-timestamp'];
    const signature   = req.headers['x-internal-signature'];

    // ── 1. Required headers ──────────────────────────────────────────────────
    if (!serviceName || !timestamp || !signature) {
      logger.warn('Internal auth: missing headers', {
        ip: req.ip,
        path: req.path,
        hasService: !!serviceName,
        hasTimestamp: !!timestamp,
        hasSignature: !!signature,
      });
      return next(AppError.forbidden('Internal endpoint requires service credentials'));
    }

    // ── 2. Service name allowlist ────────────────────────────────────────────
    if (!ALLOWED_SERVICES.has(serviceName)) {
      logger.warn('Internal auth: unknown service name', { serviceName, ip: req.ip });
      return next(AppError.forbidden('Unknown service identifier'));
    }

    // ── 3. Network-level restriction ─────────────────────────────────────────
    // Internal endpoints should only be reachable from within the service network.
    // This is a defense-in-depth check — Nginx/firewall rules are the primary control.
    const clientIp = (req.ip || '').replace(/^::ffff:/, '');
    const internalCidr = process.env.INTERNAL_NETWORK_CIDR || '127.0.0.1';
    const isLoopback = clientIp === '127.0.0.1' || clientIp === '::1';
    const isInternalNet = internalCidr.split(',').some((cidr) => clientIp.startsWith(cidr.trim().split('/')[0]));

    if (!isLoopback && !isInternalNet) {
      logger.warn('Internal auth: access from non-internal IP rejected', {
        clientIp, serviceName, path: req.path,
      });
      return next(AppError.forbidden('Internal endpoints are not accessible from this network'));
    }

    // ── 4. Timestamp freshness check ─────────────────────────────────────────
    const tsNum = parseInt(timestamp, 10);
    if (!Number.isFinite(tsNum) || Math.abs(Date.now() - tsNum) > TIMESTAMP_WINDOW_MS) {
      logger.warn('Internal auth: stale timestamp', {
        serviceName, drift: Math.abs(Date.now() - tsNum), ip: req.ip,
      });
      return next(AppError.forbidden('Internal request timestamp outside acceptable window'));
    }

    // ── 5. HMAC signature verification ───────────────────────────────────────
    let secret;
    try {
      secret = getInternalSecret();
    } catch (err) {
      logger.error('Internal auth: secret misconfiguration', { error: err.message });
      return next(AppError.internalError('Internal authentication system misconfigured'));
    }

    const canonical = buildInternalCanonical(serviceName, timestamp, req.body);
    const expected  = crypto.createHmac('sha256', secret).update(canonical).digest('hex');

    let sigBuf, expBuf;
    try {
      sigBuf = Buffer.from(signature, 'hex');
      expBuf = Buffer.from(expected,  'hex');
    } catch {
      return next(AppError.forbidden('Invalid internal signature format'));
    }

    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      logger.warn('Internal auth: HMAC verification failed', {
        serviceName, ip: req.ip, path: req.path,
      });
      return next(AppError.forbidden('Invalid internal service signature'));
    }

    // ── 6. Attach internal service identity to request ───────────────────────
    req.internalService = serviceName;

    next();
  } catch (err) {
    next(err);
  }
}

/**
 * Utility for CALLING services to sign outbound internal requests.
 * Import this in withdrawal-engine, blockchain-listener, etc.
 *
 * @param {string} serviceName - This service's identifier (must be in ALLOWED_SERVICES)
 * @param {object} [body={}]   - Request body to be sent
 * @returns {object} Headers to add to the outbound request
 */
function signInternalRequest(serviceName, body = {}) {
  const secret    = getInternalSecret();
  const timestamp = String(Date.now());
  const canonical = buildInternalCanonical(serviceName, timestamp, body);
  const signature = crypto.createHmac('sha256', secret).update(canonical).digest('hex');

  return {
    'x-internal-service':   serviceName,
    'x-internal-timestamp': timestamp,
    'x-internal-signature': signature,
    'content-type':         'application/json',
  };
}

module.exports = { internalAuth, signInternalRequest, ALLOWED_SERVICES };
