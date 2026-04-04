'use strict';

/**
 * @module controllers/ofacController
 *
 * OFAC Sanctions List Sync — Mainnet Requirement #3.
 *
 * Fetches the US Treasury Office of Foreign Assets Control (OFAC)
 * Specially Designated Nationals (SDN) list and syncs crypto wallet
 * addresses into the BlacklistedWallet collection.
 *
 * OFAC SDN List: https://www.treasury.gov/ofac/downloads/sdn.xml
 * Terms: Free public data — no API key required.
 *
 * ARCHITECTURE:
 *   - Manual trigger: POST /admin/compliance/ofac/sync (super_admin + TOTP)
 *   - Automated: Run ofacSync.js as a scheduled job (daily via cron/scheduler)
 *   - Both use the same syncOfacList() core function
 *
 * Routes:
 *   GET  /admin/compliance/ofac/status — Last sync time, count of OFAC entries
 *   POST /admin/compliance/ofac/sync   — Trigger immediate sync (super_admin)
 */

const https  = require('https');
const { parseString } = require('xml2js'); // Safe XML parser
const { BlacklistedWallet, AuditLog, SystemConfig } = require('@xcg/database');
const { AppError } = require('@xcg/common');
const asyncHandler = require('../utils/asyncHandler');
const logger = require('@xcg/logger').createLogger('ofac-sync');

const OFAC_SDN_URL     = 'https://www.treasury.gov/ofac/downloads/sdn.xml';
const OFAC_LAST_SYNC_KEY = 'compliance.ofac.lastSync';

/**
 * Fetch the OFAC SDN XML from US Treasury.
 * @returns {Promise<string>} Raw XML string
 */
function fetchOfacXml() {
  return new Promise((resolve, reject) => {
    const req = https.get(OFAC_SDN_URL, {
      timeout: 30000,
      headers: { 'User-Agent': 'XCoinGateway-Compliance/1.0 (sanctions-screening)' },
    }, (res) => {
      if (res.statusCode !== 200) {
        return reject(new Error(`OFAC fetch failed: HTTP ${res.statusCode}`));
      }

      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('OFAC fetch timed out after 30s'));
    });
    req.on('error', reject);
  });
}

/**
 * Extract crypto wallet addresses from OFAC SDN XML.
 * OFAC marks digital currency addresses with idType="Digital Currency Address - XBT" etc.
 *
 * @param {string} xml - Raw OFAC SDN XML
 * @returns {Promise<Array<{address: string, network: string, name: string}>>}
 */
function extractCryptoAddresses(xml) {
  return new Promise((resolve, reject) => {
    parseString(xml, { explicitArray: false, ignoreAttrs: false }, (err, result) => {
      if (err) return reject(new Error(`OFAC XML parse error: ${err.message}`));

      const addresses = [];
      const entries = result?.sdnList?.sdnEntry;
      if (!entries) return resolve([]);

      const entryList = Array.isArray(entries) ? entries : [entries];

      for (const entry of entryList) {
        const name = entry?.lastName || entry?.firstName || 'OFAC SDN Entry';
        const idList = entry?.idList?.id;
        if (!idList) continue;

        const ids = Array.isArray(idList) ? idList : [idList];
        for (const id of ids) {
          const idType = id?.['$']?.idType || id?.idType || '';
          const idNum  = id?.['$']?.idNumber || id?.idNumber || '';

          // Match various crypto address types in OFAC database
          if (idType.toLowerCase().includes('digital currency') || 
              idType.toLowerCase().includes('cryptocurrency') ||
              idType.toLowerCase().includes('tron') ||
              idType.toLowerCase().includes('eth') ||
              idType.toLowerCase().includes('btc') ||
              idType.toLowerCase().includes('xbt')) {
            
            let network = 'unknown';
            if (idType.toLowerCase().includes('tron') || idType.toLowerCase().includes('trx')) {
              network = 'tron';
            } else if (idType.toLowerCase().includes('eth')) {
              network = 'ethereum';
            } else if (idType.toLowerCase().includes('btc') || idType.toLowerCase().includes('xbt')) {
              network = 'bitcoin';
            }

            // Only include addresses — filter out non-address formats
            if (idNum && idNum.length >= 26) {
              addresses.push({
                address: idNum.toLowerCase().trim(),
                network,
                name:    String(name),
              });
            }
          }
        }
      }

      resolve(addresses);
    });
  });
}

/**
 * Core OFAC sync function.
 * Fetches the SDN list and upserts crypto addresses into BlacklistedWallet.
 *
 * @param {string} triggeredBy - userId of the actor triggering the sync
 * @returns {Promise<{added: number, updated: number, total: number, fetchedAt: Date}>}
 */
async function syncOfacList(triggeredBy) {
  const fetchedAt  = new Date();
  let xmlData;

  try {
    logger.info('OFAC: fetching SDN list from US Treasury', { triggeredBy });
    xmlData = await fetchOfacXml();
  } catch (err) {
    logger.error('OFAC: failed to fetch SDN list', { error: err.message });
    throw new Error(`OFAC fetch failed: ${err.message}`);
  }

  let addresses;
  try {
    addresses = await extractCryptoAddresses(xmlData);
    logger.info('OFAC: extracted crypto addresses', { count: addresses.length });
  } catch (err) {
    logger.error('OFAC: failed to parse SDN XML', { error: err.message });
    throw new Error(`OFAC parse failed: ${err.message}`);
  }

  if (addresses.length === 0) {
    logger.warn('OFAC: no crypto addresses found in SDN list — check OFAC format');
  }

  let added   = 0;
  let updated = 0;

  for (const { address, network, name } of addresses) {
    try {
      const existing = await BlacklistedWallet.findOne({ address });
      if (existing) {
        // Update notes if already exists — don't re-blacklist
        if (existing.reason === 'ofac_sanctions') {
          await BlacklistedWallet.updateOne(
            { address },
            { $set: { notes: `OFAC SDN: ${name}`, isActive: true } },
          );
          updated++;
        }
      } else {
        await BlacklistedWallet.create({
          address,
          network,
          reason:      'ofac_sanctions',
          notes:       `OFAC SDN: ${name} — synced ${fetchedAt.toISOString()}`,
          addedBy:     null,
          autoFlagged: true,
          isActive:    true,
        });
        added++;
      }
    } catch (err) {
      // Skip individual failures — don't abort the entire sync
      logger.warn('OFAC: failed to upsert address', { address, error: err.message });
    }
  }

  // Record last sync metadata in SystemConfig (if actor provided — skip required user for system)
  try {
    if (triggeredBy) {
      await SystemConfig.findOneAndUpdate(
        { key: 'compliance.ofac.lastSync' },
        {
          $set: {
            key:         'compliance.ofac.lastSync',
            value:       fetchedAt.toISOString(),
            description: `Last OFAC SDN sync: ${added} added, ${updated} updated`,
            updatedBy:   triggeredBy,
          },
        },
        { upsert: true, runValidators: false }, // Skip key whitelist for internal use
      );
    }
  } catch { /* non-critical */ }

  logger.info('OFAC: sync complete', { added, updated, total: addresses.length });
  return { added, updated, total: addresses.length, fetchedAt };
}

// ─── GET /admin/compliance/ofac/status ───────────────────────────────────────

async function getOfacSyncStatus(req, res) {
  const [ofacCount, lastSyncConfig] = await Promise.all([
    BlacklistedWallet.countDocuments({ reason: 'ofac_sanctions', isActive: true }),
    SystemConfig.findOne({ key: OFAC_LAST_SYNC_KEY }).lean().catch(() => null),
  ]);

  res.json({
    success: true,
    data: {
      activeOfacEntries: ofacCount,
      lastSyncAt:        lastSyncConfig?.value || null,
      lastSyncNote:      lastSyncConfig?.description || 'No sync recorded',
      sourceUrl:         OFAC_SDN_URL,
      recommendation:    ofacCount === 0
        ? '⚠️ No OFAC entries — trigger a sync immediately before going live'
        : `${ofacCount} OFAC-sanctioned addresses are actively blocked`,
    },
  });
}

// ─── POST /admin/compliance/ofac/sync ────────────────────────────────────────

async function triggerOfacSync(req, res) {
  logger.warn('OFAC: manual sync triggered', {
    actor: req.user.userId,
    ip:    req.ip,
  });

  const result = await syncOfacList(req.user.userId);

  await AuditLog.create({
    actor:      req.user.userId,
    action:     'admin.ofac_sync',
    resource:   'compliance',
    resourceId: 'ofac_sdn',
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   result,
  });

  res.json({
    success: true,
    data: {
      ...result,
      message: `OFAC sync complete: ${result.added} new entries, ${result.updated} updated, ${result.total} total addresses scanned`,
    },
  });
}

module.exports = {
  getOfacSyncStatus: asyncHandler(getOfacSyncStatus),
  triggerOfacSync:   asyncHandler(triggerOfacSync),
  syncOfacList,      // Exported for use by scheduled cron job
};
