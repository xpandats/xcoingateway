'use strict';

/**
 * @module models/BlockScanCursor
 *
 * Block Scan Cursor — Persistent last-scanned block number for blockchain listener.
 *
 * WHY THIS EXISTS:
 *   The blockchain listener polls TronGrid for new blocks every 3-5 seconds.
 *   On restart, it needs to know WHERE it left off to avoid:
 *     - Missing transactions (if it skips ahead)
 *     - Re-processing old transactions (if it starts from genesis)
 *
 *   Only ONE cursor per network+token combination.
 *   Leader election ensures only one instance writes to the cursor.
 *
 * SECURITY: Only the blockchain-listener leader should write to this document.
 */

const mongoose = require('mongoose');

const blockScanCursorSchema = new mongoose.Schema({
  // Unique per chain+token
  network:  { type: String, required: true },        // 'tron', 'ethereum', etc.
  token:    { type: String, required: true },        // 'USDT', 'ALL', etc.

  // Cursor position
  lastScannedBlock:     { type: Number, required: true },
  lastScannedTimestamp: { type: Date, default: null },       // Block timestamp
  lastScannedTxCount:   { type: Number, default: 0 },       // Txs found in that block

  // Health tracking
  lastPollAt:           { type: Date, default: null },       // When the listener last polled
  pollCount:            { type: Number, default: 0 },        // Total polls since startup
  errorCount:           { type: Number, default: 0 },        // Consecutive errors
  lastError:            { type: String, default: null },
  lastErrorAt:          { type: Date, default: null },

  // Provider status
  activeProvider:       { type: String, default: 'trongrid' }, // 'trongrid', 'tron_rpc', etc.
  providerFailovers:    { type: Number, default: 0 },         // Total failover count

  // Stats (for monitoring dashboard)
  totalTxsDetected:     { type: Number, default: 0 },
  totalBlocksScanned:   { type: Number, default: 0 },
}, {
  timestamps: true,
  collection: 'block_scan_cursors',
  strict: true,
});

// Unique compound index: one cursor per network+token
blockScanCursorSchema.index({ network: 1, token: 1 }, { unique: true });

module.exports = mongoose.model('BlockScanCursor', blockScanCursorSchema);
