'use strict';

/**
 * @module middleware/requestHardening
 *
 * WAF-Layer Request Hardening — Mainnet Requirement #8.
 *
 * A code-level Web Application Firewall layer that catches common attack
 * patterns BEFORE they reach business logic. This adds defense-in-depth
 * on top of Cloudflare/Nginx WAF rules.
 *
 * BLOCKS:
 *   1. Path traversal attempts (../../etc/passwd)
 *   2. Null byte injection (%00, \x00)
 *   3. Common scanner user-agents (automated attack tools)
 *   4. Oversized headers (header injection)
 *   5. Suspicious URL patterns (SQL fragments in URL)
 *   6. Host header injection
 *   7. X-Forwarded-For spoofing attempts (multiple hops beyond expected)
 *
 * ARCHITECTURE:
 *   Applied BEFORE all business logic routes in app.js.
 *   Logs every block to security logger with full request context.
 */

const { response, HttpStatus } = require('@xcg/common');
const { createLogger } = require('@xcg/logger');

const logger = createLogger('waf-hardening');

// ─── Suspicious user agents (known attack tool signatures) ────────────────────
const BLOCKED_UA_PATTERNS = [
  /sqlmap/i,
  /nikto/i,
  /nmap/i,
  /masscan/i,
  /zgrab/i,
  /nuclei/i,
  /dirbuster/i,
  /gobuster/i,
  /ffuf/i,
  /wfuzz/i,
  /burpsuite/i,
  /owasp\s*zap/i,
  /acunetix/i,
  /nessus/i,
  /openvas/i,
  /metasploit/i,
];

// ─── Path traversal patterns ──────────────────────────────────────────────────
const PATH_TRAVERSAL = /(\.\.[\/\\]|%2e%2e[\/\\%]|%252e%252e)/i;

// ─── Null byte injection ───────────────────────────────────────────────────────
const NULL_BYTE = /(%00|\x00|\u0000)/;

// ─── Suspicious URL content (common SQLi/XSS fragments in URL) ───────────────
const SUSPICIOUS_URL = /(union\s+select|select\s+from|drop\s+table|insert\s+into|exec\s*\(|eval\s*\(|<script|javascript:|vbscript:)/i;

// ─── Host header injection ────────────────────────────────────────────────────
// Allows only alphanumeric, hyphens, dots, colon (port), and brackets (IPv6)
const VALID_HOST = /^[a-zA-Z0-9\-.:[\]]+$/;

// ─── Header size limits ───────────────────────────────────────────────────────
const MAX_HEADER_SIZE   = 8192;   // 8KB per header value
const MAX_TOTAL_HEADERS = 50;     // No legitimate client sends 50+ headers

/**
 * Block the request with a standardized WAF rejection response.
 */
function block(res, req, reason, detail = '') {
  logger.warn('WAF: request blocked', {
    reason,
    detail,
    ip:        req.ip,
    method:    req.method,
    path:      req.path,
    userAgent: req.get('user-agent')?.substring(0, 100),
    requestId: req.requestId,
  });

  return res.status(HttpStatus.BAD_REQUEST).json(
    response.error('REQUEST_BLOCKED', 'Request contains invalid content'),
  );
}

/**
 * Main WAF hardening middleware.
 * Applied once to all /api/ routes in app.js.
 */
function requestHardening(req, res, next) {
  const ua  = req.get('user-agent')  || '';
  const url = req.originalUrl        || '';

  // ── 1. Blocked user agents (known attack tools) ───────────────────────────
  if (BLOCKED_UA_PATTERNS.some((p) => p.test(ua))) {
    return block(res, req, 'blocked_user_agent', ua.substring(0, 100));
  }

  // ── 2. Path traversal ─────────────────────────────────────────────────────
  if (PATH_TRAVERSAL.test(url)) {
    return block(res, req, 'path_traversal', url.substring(0, 200));
  }

  // ── 3. Null byte injection ────────────────────────────────────────────────
  if (NULL_BYTE.test(url)) {
    return block(res, req, 'null_byte_injection', 'in URL');
  }

  // Check body as string if it's been parsed as text somewhere
  if (typeof req.body === 'string' && NULL_BYTE.test(req.body)) {
    return block(res, req, 'null_byte_injection', 'in body');
  }

  // ── 4. Suspicious URL patterns ────────────────────────────────────────────
  // Only check the path/query, not headers
  if (SUSPICIOUS_URL.test(url)) {
    return block(res, req, 'suspicious_url_pattern', url.substring(0, 200));
  }

  // ── 5. Host header validation ─────────────────────────────────────────────
  const host = req.get('host') || '';
  if (host && !VALID_HOST.test(host)) {
    return block(res, req, 'host_header_injection', host.substring(0, 100));
  }

  // ── 6. Header count limit ─────────────────────────────────────────────────
  const headerCount = Object.keys(req.headers).length;
  if (headerCount > MAX_TOTAL_HEADERS) {
    return block(res, req, 'excessive_headers', `${headerCount} headers`);
  }

  // ── 7. Individual header size limit ──────────────────────────────────────
  for (const [name, value] of Object.entries(req.headers)) {
    const val = Array.isArray(value) ? value.join(',') : value;
    if (val && val.length > MAX_HEADER_SIZE) {
      return block(res, req, 'oversized_header', `header ${name}: ${val.length} chars`);
    }
    // Check for null bytes in headers
    if (val && NULL_BYTE.test(val)) {
      return block(res, req, 'null_byte_in_header', `header ${name}`);
    }
  }

  // ── 8. X-Forwarded-For chain depth check ─────────────────────────────────
  // We trust proxy level 1 only (set in app.js: trust proxy 1).
  // More than 3 IPs in XFF chain = possible IP spoofing attempt.
  const xff = req.get('x-forwarded-for') || '';
  if (xff) {
    const hopCount = xff.split(',').length;
    if (hopCount > 3) {
      // Log as warning, not block — could be legitimate load balancer chains
      logger.warn('WAF: suspicious X-Forwarded-For chain depth', {
        hopCount,
        xff:       xff.substring(0, 200),
        ip:        req.ip,
        requestId: req.requestId,
      });
    }
  }

  next();
}

module.exports = { requestHardening };
