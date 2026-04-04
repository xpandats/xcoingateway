#!/usr/bin/env node
'use strict';

/**
 * @module scripts/ofacCronJob
 *
 * OFAC SDN Automated Daily Sync — Mainnet Requirement #3 (Automated).
 *
 * Run this daily via system cron or PM2 cron-restart:
 *
 *   CRON (recommended — runs independently of PM2):
 *     0 3 * * * /usr/bin/node /home/xcg/app/scripts/ofacCronJob.js >> /var/log/xcg/ofac-sync.log 2>&1
 *
 *   PM2 (alternative — runs as a scheduled PM2 job):
 *     Add to ecosystem.config.js apps array:
 *     {
 *       name:   'xcg-ofac-sync',
 *       script: './scripts/ofacCronJob.js',
 *       cron_restart: '0 3 * * *',  // 3am daily
 *       autorestart: false,
 *     }
 *
 * WHAT IT DOES:
 *   1. Connects to MongoDB
 *   2. Calls syncOfacList() — fetches US Treasury SDN XML + upserts to BlacklistedWallet
 *   3. Exits 0 on success, 1 on failure
 */

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env.local') });

const mongoose  = require('mongoose');
const { createLogger } = require('@xcg/logger');
const { syncOfacList } = require('../services/api-server/src/controllers/ofacController');

const logger = createLogger('ofac-cron');

async function main() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    logger.error('OFAC cron: MONGODB_URI not set');
    process.exit(1);
  }

  logger.info('OFAC cron: connecting to MongoDB...');
  await mongoose.connect(uri, { serverSelectionTimeoutMS: 10000 });
  logger.info('OFAC cron: connected');

  try {
    const result = await syncOfacList('system:ofac-cron');
    logger.info('OFAC cron: sync complete', result);
    console.log(`OFAC_SYNC_SUCCESS added=${result.added} updated=${result.updated} total=${result.total}`);
    process.exit(0);
  } catch (err) {
    logger.error('OFAC cron: sync failed', { error: err.message });
    console.error(`OFAC_SYNC_FAILED error=${err.message}`);
    process.exit(1);
  } finally {
    await mongoose.disconnect();
  }
}

main().catch((err) => {
  console.error('OFAC cron: fatal error', err.message);
  process.exit(1);
});
