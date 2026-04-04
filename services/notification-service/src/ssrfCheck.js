'use strict';

/**
 * @module notification-service/ssrfCheck
 *
 * Outbound URL SSRF Protection — self-contained for notification-service.
 *
 * Blocks webhook delivery to:
 *   - Private IP ranges (RFC1918: 10.x, 172.16-31.x, 192.168.x)
 *   - Loopback (127.x, ::1)
 *   - Link-local (169.254.x — AWS metadata endpoint)
 *   - Non-HTTPS URLs
 *
 * Does NOT do DNS resolution (too slow for background webhook delivery).
 * DNS-based SSRF check is enforced at webhook URL registration time in the API server.
 */

const dns = require('dns').promises;
const net = require('net');

// Private IP ranges that must never be webhook targets
const PRIVATE_RANGES = [
  /^10\./,                          // RFC1918: 10.0.0.0/8
  /^172\.(1[6-9]|2\d|3[01])\./,   // RFC1918: 172.16.0.0/12
  /^192\.168\./,                    // RFC1918: 192.168.0.0/16
  /^127\./,                         // Loopback
  /^169\.254\./,                    // Link-local (AWS metadata)
  /^0\./,                           // 0.0.0.0/8
  /^::1$/,                          // IPv6 loopback
  /^fc00:/,                         // IPv6 unique local
  /^fe80:/,                         // IPv6 link-local
  /^::ffff:127\./,                  // IPv6-mapped loopback
];

function isPrivateIp(ip) {
  return PRIVATE_RANGES.some((r) => r.test(ip));
}

/**
 * Validate that a URL is safe to make an outbound HTTP request to.
 * Throws if the URL is unsafe.
 *
 * @param {string} url - URL to validate
 * @throws {Error} If URL is unsafe
 */
async function validateOutboundUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`SSRF: Invalid URL format: ${url}`);
  }

  // Must be HTTPS (webhooks over HTTP are insecure)
  if (parsed.protocol !== 'https:') {
    throw new Error(`SSRF: Webhook URL must use HTTPS: ${url}`);
  }

  const hostname = parsed.hostname;

  // Block direct IP addresses in URL
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) {
      throw new Error(`SSRF: Webhook URL points to private IP: ${hostname}`);
    }
    // Even public IPs in URL are suspicious — require hostnames
    throw new Error(`SSRF: Webhook URL must use a hostname, not a raw IP: ${hostname}`);
  }

  // DNS resolve and check all returned IPs
  try {
    const addresses = await dns.resolve4(hostname).catch(() => []);
    const addresses6 = await dns.resolve6(hostname).catch(() => []);
    const allIps = [...addresses, ...addresses6];

    for (const ip of allIps) {
      if (isPrivateIp(ip)) {
        throw new Error(`SSRF: Hostname ${hostname} resolves to private IP ${ip}`);
      }
    }
  } catch (err) {
    if (err.message.startsWith('SSRF:')) throw err;
    // DNS failure — block the delivery (safe fail)
    throw new Error(`SSRF: DNS resolution failed for ${hostname}: ${err.message}`);
  }
}

module.exports = { validateOutboundUrl, isPrivateIp };
