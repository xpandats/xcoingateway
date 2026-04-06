'use strict';

/**
 * @module utils/cache
 *
 * Redis Cache Utility — Bank-Grade Hot-Path Caching.
 *
 * GAPS FIXED IN THIS VERSION:
 *   Gap 1 — Active wallet list cache (xcg:cache:wallets:active, 2-min TTL)
 *   Gap 2 — Invoice amount slot occupancy cache (xcg:invoice:slot:{addr}:{amount})
 *   Gap 3 — SystemConfig cache (xcg:cache:sysconfig:{key}, 10-min TTL)
 *   Gap 4 — Cache stampede protection via getOrSet() with Redis lock-on-miss
 *   Gap 5 — Merchant cache versioning (xcg:cache:merchant:v:{id}) so profile
 *            updates bust all stale entries atomically
 *
 * SECURITY DESIGN:
 *   - Private keys, raw secrets, password hashes are NEVER cached
 *   - apiSecret encrypted blob IS cached (same security level as DB storage)
 *   - plaintext decrypted secrets are NEVER cached
 *   - All writes use EX (absolute TTL), never persist indefinitely
 *   - Cache failures ALWAYS fall back to DB (fail-open) with error logging
 *
 * STAMPEDE PROTECTION (Gap 4):
 *   Uses "single-loader lock" pattern:
 *     1. Check cache → hit: return cached value immediately
 *     2. Miss: try to acquire a short-lived Redis lock (SET NX EX 10)
 *     3. Lock acquired: call loader(), write result to cache, release lock
 *     4. Lock NOT acquired (another loader is running): short sleep + retry
 *     5. After 3 retries, call loader() directly (fail-open for reliability)
 *
 * CACHE VERSIONING (Gap 5):
 *   Merchant profiles get a version counter in Redis:
 *     xcg:cache:merchant:ver:{merchantId} → integer (incremented on every mutation)
 *   The cached profile includes the version it was built at.
 *   On read, if stored version !== current version → treat as miss.
 *   Mutations call bumpMerchantVersion() which atomically increments the counter.
 *   No need to enumerate or delete individual cache keys — version bump invalidates all.
 */

const { createLogger } = require('@xcg/logger');

const logger = createLogger('cache');

// ─── TTL constants ─────────────────────────────────────────────────────────────
const TTL = {
  MERCHANT_PROFILE:     300,  // 5 min — merchant settings change infrequently
  MERCHANT_VERSION:    86400, // 24h — version counter persists longer than any cached value
  ACTIVE_WALLETS:       120,  // 2 min — wallet list changes rarely
  SYSTEM_CONFIG:        600,  // 10 min — admin-set config values
  INVOICE_SLOT:        1800,  // 30 min — slightly longer than max invoice lifetime (20 min typical)
  STAMPEDE_LOCK:         10,  // 10s — loader must complete within this window
};

// ─── Key builders (centralised to prevent typos) ───────────────────────────────
const KEY = {
  merchantApiAuth:   (keyId)        => `xcg:cache:merchant-auth:${keyId}`,
  merchantProfile:   (id, ver = '') => `xcg:cache:merchant:${id}:v${ver}`,
  merchantVersion:   (id)           => `xcg:cache:merchant:ver:${id}`,
  activeWallets:     ()             => 'xcg:cache:wallets:active',
  systemConfig:      (key)          => `xcg:cache:sysconfig:${key}`,
  systemConfigAll:   ()             => 'xcg:cache:sysconfig:__all__',
  invoiceSlot:       (addr, amount) => `xcg:invoice:slot:${addr}:${amount}`,
  stampedelock:      (key)          => `xcg:cache:lock:${key}`,
};

// ─── Core primitives ───────────────────────────────────────────────────────────

/**
 * Get a cached value. Returns null on miss or Redis failure.
 */
async function get(redis, key) {
  if (!redis) return null;
  try {
    const raw = await redis.get(key);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch (err) {
    logger.warn('Cache GET failed — falling back to DB', { key, error: err.message });
    return null;
  }
}

/**
 * Set a cached value with TTL (seconds).
 */
async function set(redis, key, value, ttl) {
  if (!redis) return;
  try {
    await redis.set(key, JSON.stringify(value), 'EX', ttl);
  } catch (err) {
    logger.warn('Cache SET failed — no effect on correctness', { key, error: err.message });
  }
}

/**
 * Delete a cached entry.
 */
async function del(redis, key) {
  if (!redis) return;
  try {
    await redis.del(key);
  } catch (err) {
    logger.warn('Cache DEL failed', { key, error: err.message });
  }
}

/**
 * Delete multiple keys matching a pattern.
 * Uses SCAN (not KEYS) to avoid blocking Redis on large keyspaces.
 */
async function delPattern(redis, pattern) {
  if (!redis) return;
  try {
    let cursor = '0';
    do {
      const [nextCursor, keys] = await redis.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
      cursor = nextCursor;
      if (keys.length > 0) {
        await redis.del(...keys);
        logger.debug('Cache: invalidated keys by pattern', { pattern, count: keys.length });
      }
    } while (cursor !== '0');
  } catch (err) {
    logger.warn('Cache pattern DEL failed', { pattern, error: err.message });
  }
}

// ─── Gap 4: Stampede Protection ────────────────────────────────────────────────

/**
 * Get-or-set with single-loader lock (thundering-herd / cache stampede protection).
 *
 * PROBLEM: When a key expires under load, N concurrent requests all miss the cache
 * simultaneously and all hit MongoDB at the same time — "thundering herd".
 *
 * SOLUTION: Only ONE caller at a time runs the loader. Others wait briefly then
 * either get the freshly-populated cache or call the loader themselves as fallback.
 *
 * FAILURE MODE: If the lock-holder crashes mid-load, the lock auto-expires (lockTtl=10s).
 * The next requester gets the lock and retries the load. Total extra latency: ≤10s.
 *
 * @param {object}   redis          - IORedis client
 * @param {string}   key            - Cache key
 * @param {number}   ttl            - Cache TTL (seconds)
 * @param {Function} loader         - Async function that loads from DB: () => Promise<value>
 * @param {number}   [lockTtl=10]   - How long the loader lock lives (seconds)
 * @param {number}   [maxRetries=3] - How many times to retry waiting for the lock
 * @returns {Promise<*>} Cached or freshly-loaded value
 */
async function getOrSet(redis, key, ttl, loader, lockTtl = TTL.STAMPEDE_LOCK, maxRetries = 3) {
  // 1. Fast path: cache hit
  const cached = await get(redis, key);
  if (cached !== null) return cached;

  const lockKey = KEY.stampedelock(key);

  // 2. Try to acquire loader lock
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    // Re-check cache before each lock attempt (another loader may have just written)
    if (attempt > 0) {
      const freshen = await get(redis, key);
      if (freshen !== null) return freshen;
    }

    if (redis) {
      const locked = await redis.set(lockKey, '1', 'EX', lockTtl, 'NX').catch(() => null);

      if (locked === 'OK') {
        // We are the loader — call loader, write cache, release lock
        try {
          const value = await loader();
          await set(redis, key, value, ttl);
          return value;
        } finally {
          await redis.del(lockKey).catch(() => null);
        }
      }

      // Lock not acquired — another loader is running. Wait and retry.
      if (attempt < maxRetries) {
        const jitterMs = 100 + Math.floor(Math.random() * 200); // 100–300ms
        await new Promise((r) => setTimeout(r, jitterMs));
      }
    } else {
      // No Redis — go straight to DB
      break;
    }
  }

  // 3. Fallback: all retries exhausted, call loader directly (no cache write)
  logger.warn('Cache stampede lock timeout — calling loader directly', { key });
  return loader();
}

// ─── Gap 5: Merchant Cache Versioning ─────────────────────────────────────────

/**
 * Get current version counter for a merchant.
 * Version starts at 1; incremented on every mutation.
 *
 * @param {object} redis
 * @param {string} merchantId
 * @returns {Promise<number>}
 */
async function getMerchantVersion(redis, merchantId) {
  if (!redis) return 0;
  try {
    const ver = await redis.get(KEY.merchantVersion(merchantId));
    return ver ? parseInt(ver, 10) : 0;
  } catch {
    return 0;
  }
}

/**
 * Increment merchant version counter. Called on EVERY mutation (key add/revoke,
 * profile update, suspension, fee change, etc.).
 *
 * A version bump atomically invalidates ALL cached values for this merchant —
 * no need to enumerate individual cache keys. Any reader that compares its cached
 * version against the current version will see a mismatch and treat it as a miss.
 *
 * @param {object} redis
 * @param {string} merchantId
 * @returns {Promise<number>} New version number
 */
async function bumpMerchantVersion(redis, merchantId) {
  if (!redis) return 0;
  try {
    // INCR is atomic — safe under concurrent mutations
    const newVer = await redis.incr(KEY.merchantVersion(merchantId));
    // Keep version counter alive as long as merchant data might be cached
    await redis.expire(KEY.merchantVersion(merchantId), TTL.MERCHANT_VERSION);
    return newVer;
  } catch (err) {
    logger.warn('Cache: failed to bump merchant version', { merchantId, error: err.message });
    return 0;
  }
}

/**
 * Cache a merchant profile with its current version embedded.
 * Use getMerchantProfileCached() to read with version validation.
 *
 * @param {object} redis
 * @param {string} merchantId
 * @param {object} profile - Safe merchant data (no secrets)
 */
async function setMerchantProfileCached(redis, merchantId, profile) {
  if (!redis) return;
  const ver = await getMerchantVersion(redis, merchantId);
  const entry = { ver, profile };
  await set(redis, KEY.merchantProfile(merchantId, ver), entry, TTL.MERCHANT_PROFILE);
}

/**
 * Read a merchant profile from cache with version validation.
 * Returns null if cache miss OR version mismatch (stale).
 *
 * @param {object} redis
 * @param {string} merchantId
 * @returns {Promise<object|null>} Merchant profile or null
 */
async function getMerchantProfileCached(redis, merchantId) {
  if (!redis) return null;
  const currentVer = await getMerchantVersion(redis, merchantId);
  if (currentVer === 0) return null; // No version recorded yet = never cached
  const entry = await get(redis, KEY.merchantProfile(merchantId, currentVer));
  if (!entry) return null;
  // Double-check: entry version matches current (guards against race between INCR and DEL)
  if (entry.ver !== currentVer) return null;
  return entry.profile;
}

// ─── Gap 1: Active Wallet List Cache ──────────────────────────────────────────

/**
 * Get active wallet list with stampede protection.
 * Used by: blockchain-listener, withdrawal-engine, matching-engine.
 *
 * NOTE: Stores only {_id, address, type, balance} — never encryptedPrivateKey.
 *
 * @param {object} redis
 * @param {Function} dbLoader - async () => wallet[] from MongoDB
 * @returns {Promise<object[]>} Active wallets
 */
async function getActiveWallets(redis, dbLoader) {
  return getOrSet(redis, KEY.activeWallets(), TTL.ACTIVE_WALLETS, dbLoader);
}

/**
 * Force-invalidate the active wallet list cache.
 * Call after: adding a wallet, disabling a wallet, balance update.
 */
async function invalidateWallets(redis) {
  await del(redis, KEY.activeWallets());
}

// ─── Gap 2: Invoice Slot Occupancy Cache ──────────────────────────────────────

/**
 * Mark a (walletAddress, uniqueAmount) pair as occupied.
 * Prevents multiple concurrent invoice creations picking the same slot.
 *
 * TTL matches max invoice lifetime + buffer. When an invoice expires or is
 * confirmed, the slot is explicitly released via releaseInvoiceSlot().
 *
 * @param {object} redis
 * @param {string} walletAddress   - TRC20 address
 * @param {number} uniqueAmount    - Unique invoice amount (6dp)
 * @param {number} [ttl]           - Slot reservation TTL in seconds
 * @returns {Promise<boolean>} true if slot was free and is now reserved, false if already taken
 */
async function reserveInvoiceSlot(redis, walletAddress, uniqueAmount, ttl = TTL.INVOICE_SLOT) {
  if (!redis) return true; // No Redis — assume free (DB collision check still runs)
  try {
    const key    = KEY.invoiceSlot(walletAddress, uniqueAmount);
    const result = await redis.set(key, '1', 'EX', ttl, 'NX');
    return result === 'OK'; // 'OK' = slot was free; null = already taken
  } catch (err) {
    logger.warn('Cache: invoice slot reserve failed — falling through to DB check', {
      walletAddress, uniqueAmount, error: err.message,
    });
    return true; // Fail-open: DB unique constraint is the final guard
  }
}

/**
 * Check if a (walletAddress, uniqueAmount) slot is currently occupied.
 *
 * @param {object} redis
 * @param {string} walletAddress
 * @param {number} uniqueAmount
 * @returns {Promise<boolean>} true if occupied
 */
async function isInvoiceSlotOccupied(redis, walletAddress, uniqueAmount) {
  if (!redis) return false;
  try {
    const key    = KEY.invoiceSlot(walletAddress, uniqueAmount);
    const result = await redis.exists(key);
    return result === 1;
  } catch (err) {
    logger.warn('Cache: invoice slot check failed — assuming free', { error: err.message });
    return false;
  }
}

/**
 * Release a (walletAddress, uniqueAmount) slot.
 * Call when: invoice confirmed, invoice expired, invoice cancelled.
 *
 * @param {object} redis
 * @param {string} walletAddress
 * @param {number} uniqueAmount
 */
async function releaseInvoiceSlot(redis, walletAddress, uniqueAmount) {
  await del(redis, KEY.invoiceSlot(walletAddress, uniqueAmount));
}

// ─── Gap 3: SystemConfig Cache ────────────────────────────────────────────────

/**
 * Get a system config value with caching.
 * Used by any service that reads SystemConfig frequently (fee rates, limits, flags).
 *
 * @param {object} redis
 * @param {string} configKey         - SystemConfig.key
 * @param {Function} dbLoader        - async () => config value from MongoDB
 * @returns {Promise<*>} Config value or null
 */
async function getSystemConfigCached(redis, configKey, dbLoader) {
  return getOrSet(redis, KEY.systemConfig(configKey), TTL.SYSTEM_CONFIG, dbLoader);
}

/**
 * Bust the cache for a specific config key (and the all-configs cache).
 * Call after: updateSystemConfig.
 *
 * @param {object} redis
 * @param {string} configKey
 */
async function invalidateSystemConfig(redis, configKey) {
  await Promise.all([
    del(redis, KEY.systemConfig(configKey)),
    del(redis, KEY.systemConfigAll()),
  ]);
}

// ─── Merchant auth cache invalidation (existing, upgraded with version bump) ──

/**
 * Invalidate all merchant-related cache entries.
 * Now also bumps merchant version counter to atomically invalidate
 * any profile caches written with old version keys.
 *
 * @param {object} redis
 * @param {string} merchantId       - MongoDB ObjectId string
 * @param {string[]} [keyIds=[]]    - API key IDs to also invalidate
 */
async function invalidateMerchant(redis, merchantId, keyIds = []) {
  // 1. Bump version → all profile caches built with old version are now stale
  await bumpMerchantVersion(redis, merchantId);
  // 2. Explicitly delete auth-cache entries for each key (these are keyed by keyId not merchantId)
  for (const keyId of keyIds) {
    await del(redis, KEY.merchantApiAuth(keyId));
  }
}

module.exports = {
  // Core
  get,
  set,
  del,
  delPattern,
  // Gap 4: Stampede protection
  getOrSet,
  // Gap 5: Merchant versioning
  getMerchantVersion,
  bumpMerchantVersion,
  setMerchantProfileCached,
  getMerchantProfileCached,
  // Gap 1: Active wallets
  getActiveWallets,
  invalidateWallets,
  // Gap 2: Invoice slots
  reserveInvoiceSlot,
  isInvoiceSlotOccupied,
  releaseInvoiceSlot,
  // Gap 3: SystemConfig
  getSystemConfigCached,
  invalidateSystemConfig,
  // Merchant auth invalidation (now with version bump)
  invalidateMerchant,
  // Constants
  KEY,
  TTL,
};
