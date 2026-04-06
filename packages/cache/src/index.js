'use strict';

/**
 * @module @xcg/cache
 *
 * Shared Redis Cache Utility — used by all XCoinGateway services.
 *
 * This is the canonical source. services/api-server/src/utils/cache.js
 * re-exports from here for backward compatibility.
 *
 * Services using this:
 *   - api-server        (merchant auth, invoice slots, sysconfig)
 *   - blockchain-listener (active wallet list)
 *   - withdrawal-engine  (active wallet list, hot wallet selection)
 *   - matching-engine    (active wallet list)
 *   - reconciliation-svc (active wallet list)
 *
 * See full documentation in api-server/src/utils/cache.js (mirrors this exactly).
 */

const { createLogger } = require('@xcg/logger');

const logger = createLogger('cache');

// ─── TTL constants ─────────────────────────────────────────────────────────────
const TTL = {
  MERCHANT_PROFILE:     300,
  MERCHANT_VERSION:    86400,
  ACTIVE_WALLETS:       120,
  SYSTEM_CONFIG:        600,
  INVOICE_SLOT:        1800,
  STAMPEDE_LOCK:         10,
};

// ─── Key builders ─────────────────────────────────────────────────────────────
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

async function set(redis, key, value, ttl) {
  if (!redis) return;
  try {
    await redis.set(key, JSON.stringify(value), 'EX', ttl);
  } catch (err) {
    logger.warn('Cache SET failed', { key, error: err.message });
  }
}

async function del(redis, key) {
  if (!redis) return;
  try {
    await redis.del(key);
  } catch (err) {
    logger.warn('Cache DEL failed', { key, error: err.message });
  }
}

async function delPattern(redis, pattern) {
  if (!redis) return;
  try {
    let cursor = '0';
    do {
      const [nextCursor, keys] = await redis.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
      cursor = nextCursor;
      if (keys.length > 0) {
        await redis.del(...keys);
      }
    } while (cursor !== '0');
  } catch (err) {
    logger.warn('Cache pattern DEL failed', { pattern, error: err.message });
  }
}

// ─── Gap 4: Stampede protection ───────────────────────────────────────────────

async function getOrSet(redis, key, ttl, loader, lockTtl = TTL.STAMPEDE_LOCK, maxRetries = 3) {
  const cached = await get(redis, key);
  if (cached !== null) return cached;

  const lockKey = KEY.stampedelock(key);

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    if (attempt > 0) {
      const freshen = await get(redis, key);
      if (freshen !== null) return freshen;
    }

    if (redis) {
      const locked = await redis.set(lockKey, '1', 'EX', lockTtl, 'NX').catch(() => null);

      if (locked === 'OK') {
        try {
          const value = await loader();
          await set(redis, key, value, ttl);
          return value;
        } finally {
          await redis.del(lockKey).catch(() => null);
        }
      }

      if (attempt < maxRetries) {
        const jitterMs = 100 + Math.floor(Math.random() * 200);
        await new Promise((r) => setTimeout(r, jitterMs));
      }
    } else {
      break;
    }
  }

  logger.warn('Cache stampede lock timeout — calling loader directly', { key });
  return loader();
}

// ─── Gap 5: Merchant cache versioning ─────────────────────────────────────────

async function getMerchantVersion(redis, merchantId) {
  if (!redis) return 0;
  try {
    const ver = await redis.get(KEY.merchantVersion(merchantId));
    return ver ? parseInt(ver, 10) : 0;
  } catch {
    return 0;
  }
}

async function bumpMerchantVersion(redis, merchantId) {
  if (!redis) return 0;
  try {
    const newVer = await redis.incr(KEY.merchantVersion(merchantId));
    await redis.expire(KEY.merchantVersion(merchantId), TTL.MERCHANT_VERSION);
    return newVer;
  } catch (err) {
    logger.warn('Cache: failed to bump merchant version', { merchantId, error: err.message });
    return 0;
  }
}

async function setMerchantProfileCached(redis, merchantId, profile) {
  if (!redis) return;
  const ver = await getMerchantVersion(redis, merchantId);
  await set(redis, KEY.merchantProfile(merchantId, ver), { ver, profile }, TTL.MERCHANT_PROFILE);
}

async function getMerchantProfileCached(redis, merchantId) {
  if (!redis) return null;
  const currentVer = await getMerchantVersion(redis, merchantId);
  if (currentVer === 0) return null;
  const entry = await get(redis, KEY.merchantProfile(merchantId, currentVer));
  if (!entry) return null;
  if (entry.ver !== currentVer) return null;
  return entry.profile;
}

// ─── Gap 1: Active wallet list ────────────────────────────────────────────────

async function getActiveWallets(redis, dbLoader) {
  return getOrSet(redis, KEY.activeWallets(), TTL.ACTIVE_WALLETS, dbLoader);
}

async function invalidateWallets(redis) {
  await del(redis, KEY.activeWallets());
}

// ─── Gap 2: Invoice slot occupancy ────────────────────────────────────────────

async function reserveInvoiceSlot(redis, walletAddress, uniqueAmount, ttl = TTL.INVOICE_SLOT) {
  if (!redis) return true;
  try {
    const key    = KEY.invoiceSlot(walletAddress, uniqueAmount);
    const result = await redis.set(key, '1', 'EX', ttl, 'NX');
    return result === 'OK';
  } catch (err) {
    logger.warn('Cache: invoice slot reserve failed — falling through to DB check', {
      walletAddress, uniqueAmount, error: err.message,
    });
    return true;
  }
}

async function isInvoiceSlotOccupied(redis, walletAddress, uniqueAmount) {
  if (!redis) return false;
  try {
    const key    = KEY.invoiceSlot(walletAddress, uniqueAmount);
    const result = await redis.exists(key);
    return result === 1;
  } catch {
    return false;
  }
}

async function releaseInvoiceSlot(redis, walletAddress, uniqueAmount) {
  await del(redis, KEY.invoiceSlot(walletAddress, uniqueAmount));
}

// ─── Gap 3: SystemConfig cache ────────────────────────────────────────────────

async function getSystemConfigCached(redis, configKey, dbLoader) {
  return getOrSet(redis, KEY.systemConfig(configKey), TTL.SYSTEM_CONFIG, dbLoader);
}

async function invalidateSystemConfig(redis, configKey) {
  await Promise.all([
    del(redis, KEY.systemConfig(configKey)),
    del(redis, KEY.systemConfigAll()),
  ]);
}

// ─── Merchant auth invalidation (with version bump) ───────────────────────────

async function invalidateMerchant(redis, merchantId, keyIds = []) {
  await bumpMerchantVersion(redis, merchantId);
  for (const keyId of keyIds) {
    await del(redis, KEY.merchantApiAuth(keyId));
  }
}

module.exports = {
  get,
  set,
  del,
  delPattern,
  getOrSet,
  getMerchantVersion,
  bumpMerchantVersion,
  setMerchantProfileCached,
  getMerchantProfileCached,
  getActiveWallets,
  invalidateWallets,
  reserveInvoiceSlot,
  isInvoiceSlotOccupied,
  releaseInvoiceSlot,
  getSystemConfigCached,
  invalidateSystemConfig,
  invalidateMerchant,
  KEY,
  TTL,
};
