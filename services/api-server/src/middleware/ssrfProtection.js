'use strict';

/**
 * @module middleware/ssrfProtection
 *
 * SSRF-1: Server-Side Request Forgery Protection.
 *
 * ATTACK: Merchant sets callbackUrl to internal EC2 metadata endpoint:
 *   http://169.254.169.254/latest/meta-data/  → leaks AWS credentials
 *   http://localhost:27017/admin               → accesses MongoDB directly
 *   http://10.0.0.1/admin                     → accesses internal network
 *
 * This middleware validates any URL that the server will make outbound
 * requests to (webhook URLs, callback URLs, etc.).
 *
 * Block list:
 *   - Private IPv4 ranges (RFC 1918)
 *   - Loopback addresses
 *   - Link-local addresses (AWS/GCP metadata: 169.254.x.x)
 *   - IPv6 loopback and link-local
 *   - Cloud metadata endpoints (hardcoded)
 */

const dns = require('dns').promises;
const net = require('net');

// RFC 1918 private + special ranges that must never be fetched
const BLOCKED_RANGES = [
  // IPv4 private
  { start: '10.0.0.0',       prefix: 8  },
  { start: '172.16.0.0',     prefix: 12 },
  { start: '192.168.0.0',    prefix: 16 },
  // Loopback
  { start: '127.0.0.0',      prefix: 8  },
  // Link-local (AWS metadata service: 169.254.169.254)
  { start: '169.254.0.0',    prefix: 16 },
  // RFC 6598 shared address space (ISP-level NAT)
  { start: '100.64.0.0',     prefix: 10 },
  // Multicast
  { start: '224.0.0.0',      prefix: 4  },
  // Broadcast / reserved
  { start: '240.0.0.0',      prefix: 4  },
];

function _ipToLong(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function _isPrivateIpv4(ip) {
  const ipLong = _ipToLong(ip);
  return BLOCKED_RANGES.some(({ start, prefix }) => {
    const maskBits = 32 - prefix;
    const rangeStart = _ipToLong(start) >>> 0;
    // eslint-disable-next-line no-bitwise
    return (ipLong >>> maskBits) === (rangeStart >>> maskBits);
  });
}

function _isPrivateIpv6(ip) {
  const normalized = ip.toLowerCase();
  return (
    normalized === '::1' ||               // loopback
    normalized.startsWith('fc') ||        // unique local
    normalized.startsWith('fd') ||        // unique local
    normalized.startsWith('fe80') ||      // link-local
    normalized.startsWith('::ffff:127')   // IPv4-mapped loopback
  );
}

/**
 * Validate that a URL is safe for the server to make outbound requests to.
 * Throws if the URL is blocked.
 *
 * @param {string} url - URL to validate
 * @throws {Error} If URL resolves to a private/blocked address
 */
async function validateOutboundUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('Invalid URL format');
  }

  // Only HTTPS allowed for outbound requests (no HTTP, no other schemes)
  if (parsed.protocol !== 'https:') {
    throw new Error('Outbound URL must use HTTPS');
  }

  const hostname = parsed.hostname;

  // Reject if hostname is a direct IP address
  if (net.isIP(hostname)) {
    if (net.isIPv4(hostname) && _isPrivateIpv4(hostname)) {
      throw new Error(`SSRF blocked: private IPv4 address not allowed`);
    }
    if (net.isIPv6(hostname) && _isPrivateIpv6(hostname)) {
      throw new Error(`SSRF blocked: private IPv6 address not allowed`);
    }
  }

  // DNS resolution check (SSRF via DNS rebinding)
  // Even if hostname looks public, it might resolve to a private IP
  try {
    const addresses = await dns.lookup(hostname, { all: true });
    for (const { address, family } of addresses) {
      if (family === 4 && _isPrivateIpv4(address)) {
        throw new Error(`SSRF blocked: ${hostname} resolves to private IPv4 ${address}`);
      }
      if (family === 6 && _isPrivateIpv6(address)) {
        throw new Error(`SSRF blocked: ${hostname} resolves to private IPv6 ${address}`);
      }
    }
  } catch (err) {
    // Re-throw SSRF blocks; DNS failures are network errors
    if (err.message.startsWith('SSRF blocked')) throw err;
    throw new Error(`Cannot resolve hostname: ${hostname}`);
  }
}

/**
 * Express middleware: validate req.body.callbackUrl or req.body.webhookUrl
 * before allowing the request to proceed.
 *
 * Use on invoice creation and merchant webhook update routes.
 */
async function ssrfProtectWebhookUrl(req, _res, next) {
  const url = req.body?.callbackUrl || req.body?.webhookUrl;
  if (!url) return next();

  try {
    await validateOutboundUrl(url);
    next();
  } catch (err) {
    const { AppError, ErrorCodes } = require('@xcg/common');
    return next(AppError.badRequest(`Webhook URL rejected: ${err.message}`, ErrorCodes.VALIDATION_FAILED));
  }
}

module.exports = { validateOutboundUrl, ssrfProtectWebhookUrl };
