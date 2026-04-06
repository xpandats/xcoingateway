'use strict';

/**
 * @module utils/money
 *
 * BL-5: Safe Financial Arithmetic Utility.
 *
 * WHY: JavaScript Number uses 64-bit IEEE 754 floats.
 * Financial arithmetic with floats loses precision:
 *   1000000.001 + 0.000001 = 1000000.0010010001  (WRONG)
 *   0.1 + 0.2 = 0.30000000000000004             (WRONG)
 *
 * For a payment system, precision errors = lost/stolen money.
 *
 * RULE: ALL financial arithmetic MUST go through these helpers.
 * NEVER use +, -, *, / directly on USDT amounts.
 *
 * Uses: integer arithmetic scaled by 10^8 (satoshi-like precision).
 * Max safe value: 2^53 / 10^8 = ~90,000,000 USDT (well above our limits)
 */

const SCALE = 100_000_000n; // 10^8 precision (8 decimal places, like Bitcoin satoshis)

/**
 * Convert a human-readable amount (string or number) to internal integer units.
 * @param {string|number} amount - e.g. "150.000347"
 * @returns {bigint} Internal units (e.g. 15000034700n)
 */
function toUnits(amount) {
  // Use string manipulation to avoid float issues
  const str = String(amount);
  const [intPart = '0', decPart = ''] = str.split('.');
  // Pad or truncate decimal part to 8 places
  const paddedDec = decPart.padEnd(8, '0').slice(0, 8);
  return BigInt(intPart) * SCALE + BigInt(paddedDec);
}

/**
 * Convert internal integer units back to a human-readable decimal string.
 * @param {bigint} units - Internal units
 * @returns {string} e.g. "150.00034700"
 */
function fromUnits(units) {
  const isNegative = units < 0n;
  const abs = isNegative ? -units : units;
  const intPart = abs / SCALE;
  const decPart = abs % SCALE;
  const decStr = decPart.toString().padStart(8, '0');
  const result = `${intPart}.${decStr}`;
  return isNegative ? `-${result}` : result;
}

/**
 * Add two amounts. Returns human-readable string.
 * @param {string|number} a
 * @param {string|number} b
 * @returns {string}
 */
function add(a, b) {
  return fromUnits(toUnits(a) + toUnits(b));
}

/**
 * Subtract b from a. Returns human-readable string.
 * @param {string|number} a
 * @param {string|number} b
 * @returns {string}
 */
function subtract(a, b) {
  return fromUnits(toUnits(a) - toUnits(b));
}

/**
 * Multiply amount by a factor (e.g. for fee calculation).
 * @param {string|number} amount
 * @param {string|number} factor - e.g. "0.01" for 1% fee
 * @returns {string}
 */
function multiply(amount, factor) {
  // Multiply in integer space then scale back
  return fromUnits((toUnits(amount) * toUnits(factor)) / SCALE);
}

/**
 * Compare two amounts.
 * @returns {number} negative if a<b, 0 if equal, positive if a>b
 */
function compare(a, b) {
  const ua = toUnits(a);
  const ub = toUnits(b);
  if (ua < ub) return -1;
  if (ua > ub) return 1;
  return 0;
}

/**
 * Check if amount is greater than zero and within acceptable bounds.
 * @param {string|number} amount
 * @returns {boolean}
 */
function isValidAmount(amount) {
  try {
    const units = toUnits(amount);
    return units > 0n && units <= toUnits('1000000'); // Max 1M USDT per transaction
  } catch {
    return false;
  }
}

/**
 * Format for display (strip trailing zeros).
 * @param {string|number} amount
 * @returns {string} e.g. "150.0003" not "150.00030000"
 */
function format(amount) {
  return fromUnits(toUnits(amount)).replace(/\.?0+$/, '');
}

/**
 * Round amount to N decimal places using integer arithmetic (no float drift).
 * Used by the Matching Engine for fee calculations.
 * @param {string|number} amount
 * @param {number} decimalPlaces - number of significant decimal places to keep (max 8)
 * @returns {number} Rounded float (safe for numbers within our 90M USDT limit)
 */
function round(amount, decimalPlaces) {
  const dp     = Math.max(0, Math.min(8, Math.floor(decimalPlaces)));
  const factor = 10 ** dp;
  // Use integer math: toUnits gives 8dp precision, divide by (10^(8-dp)) to get dp precision
  const units  = toUnits(amount);
  const divBy  = BigInt(10 ** (8 - dp));
  const rounded = (units + divBy / 2n) / divBy;
  return Number(rounded) / factor;
}

module.exports = { toUnits, fromUnits, add, subtract, multiply, compare, isValidAmount, format, round };
