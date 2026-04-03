'use strict';

/**
 * @module blockchain-listener/listener
 *
 * Core Blockchain Polling Loop — Tron USDT TRC20.
 *
 * BEHAVIOUR:
 *   - Polls TronGrid every 4 seconds for new blocks
 *   - For every new block: scans all USDT TRC20 transfers to our wallets
 *   - Publishes detected transactions to Redis queue (HMAC-signed)
 *   - Persists last scanned block in DB so restarts resume without gaps
 *   - Detects stale blocks (no new block in 30s) and fires alert
 *
 * SECURITY:
 *   - TX hashes deduplicated (Redis seen-set, 7-day TTL)
 *   - USDT contract address is HARDCODED in adapter — not from config
 *   - Never credits 0-conf transactions — blockNum included in event payload
 *   - Provider automatically rotates to fallback on TronGrid failure
 *   - All published messages HMAC-signed (authenticated by Matching Engine)
 *
 * FAULT TOLERANCE:
 *   - State (lastScannedBlock) persisted to DB — survives restarts
 *   - On startup, resumes from last saved block (no gaps)
 *   - Single block failure: logs error and continues (skip + alert)
 *   - Circuit breaker: if 5 consecutive blocks fail → alert + pause
 */

const { SystemConfig, Wallet } = require('@xcg/database');

const DEDUP_KEY_PREFIX  = 'xcg:txseen:';
const DEDUP_TTL_SECONDS = 7 * 24 * 60 * 60; // 7 days
const CIRCUIT_BREAKER_THRESHOLD = 5;

class BlockchainListener {
  /**
   * @param {object} opts
   * @param {object} opts.adapter        - TronAdapter instance
   * @param {object} opts.redis          - IORedis instance (for deduplication)
   * @param {object} opts.publisher      - Queue publisher for TRANSACTION_DETECTED
   * @param {object} opts.alertPublisher - Queue publisher for SYSTEM_ALERT
   * @param {object} opts.config         - config.tron
   * @param {object} opts.logger         - @xcg/logger instance
   */
  constructor({ adapter, redis, publisher, alertPublisher, config, logger }) {
    this.adapter        = adapter;
    this.redis          = redis;
    this.publisher      = publisher;
    this.alertPublisher = alertPublisher;
    this.config         = config;
    this.logger         = logger;

    this._running           = false;
    this._timer             = null;
    this._lastBlockTime     = null;
    this._consecutiveErrors = 0;
    this._walletAddresses   = new Set(); // Cache of our wallet addresses (refreshed every 60s)
    this._walletRefreshAt   = 0;
  }

  // ─── Lifecycle ──────────────────────────────────────────────────────────────

  async start() {
    this.logger.info('BlockchainListener: starting');
    this._running = true;

    // Load wallet addresses before first poll
    await this._refreshWalletAddresses();

    // Schedule first tick immediately
    this._scheduleNext(0);
    this.logger.info('BlockchainListener: started');
  }

  stop() {
    this._running = false;
    if (this._timer) clearTimeout(this._timer);
    this.logger.info('BlockchainListener: stopped');
  }

  _scheduleNext(delayMs) {
    if (!this._running) return;
    this._timer = setTimeout(() => this._tick(), delayMs);
  }

  // ─── Main Polling Tick ───────────────────────────────────────────────────────

  async _tick() {
    const pollIntervalMs = this.config.pollIntervalMs || 4000;

    try {
      await this._poll();
      this._consecutiveErrors = 0; // Reset circuit breaker on success
    } catch (err) {
      this._consecutiveErrors++;
      this.logger.error('BlockchainListener: tick error', {
        error: err.message,
        consecutiveErrors: this._consecutiveErrors,
      });

      // Circuit breaker: N consecutive failures → alert + longer pause
      if (this._consecutiveErrors >= CIRCUIT_BREAKER_THRESHOLD) {
        await this._fireAlert('blockchain_circuit_open', {
          message: `${this._consecutiveErrors} consecutive polling errors`,
          error: err.message,
        });
        this._scheduleNext(pollIntervalMs * 10); // Back off 10x
        return;
      }
    }

    // Check for stale blocks
    await this._checkStaleness();

    this._scheduleNext(pollIntervalMs);
  }

  // ─── Polling Logic ───────────────────────────────────────────────────────────

  async _poll() {
    const latestBlock = await this.adapter.getLatestBlock();
    const lastScanned = await this._getLastScannedBlock();

    if (latestBlock <= lastScanned) {
      // No new blocks yet — this is normal
      return;
    }

    // Process each new block (may be multiple if we were behind)
    // Cap at 20 blocks max per tick to avoid overload on restart
    const fromBlock = lastScanned + 1;
    const toBlock   = Math.min(latestBlock, lastScanned + 20);

    for (let blockNum = fromBlock; blockNum <= toBlock; blockNum++) {
      try {
        await this._processBlock(blockNum, latestBlock);
        await this._setLastScannedBlock(blockNum);
        this._lastBlockTime = Date.now();
      } catch (err) {
        this.logger.error('BlockchainListener: failed to process block', {
          blockNum,
          error: err.message,
        });
        // Do NOT update lastScannedBlock — will retry this block next tick
        throw err;
      }
    }
  }

  async _processBlock(blockNum, latestBlock) {
    // Refresh wallet address cache every 60 seconds
    if (Date.now() - this._walletRefreshAt > 60_000) {
      await this._refreshWalletAddresses();
    }

    if (this._walletAddresses.size === 0) {
      this.logger.debug('BlockchainListener: no active wallets — skipping block', { blockNum });
      return;
    }

    const transfers = await this.adapter.getTransfersInBlock(blockNum);

    for (const transfer of transfers) {
      // Only process transfers TO our wallets
      if (!this._walletAddresses.has(transfer.toAddress.toLowerCase())) {
        continue;
      }

      await this._handleTransfer(transfer, latestBlock);
    }
  }

  async _handleTransfer(transfer, latestBlock) {
    const { txHash, blockNum } = transfer;

    // SECURITY: Deduplicate by TX hash (Redis seen-set)
    // Prevents double-processing of the same transaction
    const dedupKey = `${DEDUP_KEY_PREFIX}${txHash}`;
    const alreadySeen = await this.redis.set(dedupKey, '1', 'EX', DEDUP_TTL_SECONDS, 'NX');

    if (alreadySeen === null) {
      // Key already existed — this TX was already published
      this.logger.debug('BlockchainListener: duplicate TX skipped', { txHash });
      return;
    }

    // Compute current confirmation count
    const confirmations = latestBlock - blockNum;

    // Publish to matching engine queue (HMAC-signed)
    // NOTE: We do NOT enforce confirmations here — the Matching Engine enforces
    // minimum confirmations before crediting. This way we can track the TX lifecycle.
    const eventData = {
      txHash,
      blockNum,
      confirmations,
      fromAddress: transfer.fromAddress,
      toAddress: transfer.toAddress,
      amount: transfer.amount,       // USDT string with 6dp (e.g. "150.000347")
      amountRaw: transfer.amountRaw, // Sun integer string
      tokenContract: transfer.tokenContract,
      tokenSymbol: transfer.tokenSymbol,
      network: transfer.network,
      timestamp: transfer.timestamp,
      detectedAt: Date.now(),
    };

    await this.publisher.publish(eventData, txHash); // idempotencyKey = txHash

    this.logger.info('BlockchainListener: transaction detected', {
      txHash,
      toAddress: transfer.toAddress,
      amount: transfer.amount,
      confirmations,
      blockNum,
    });
  }

  // ─── Wallet Address Cache ────────────────────────────────────────────────────

  async _refreshWalletAddresses() {
    try {
      const wallets = await Wallet.find(
        { isActive: true },
        { address: 1 },
      ).lean();
      this._walletAddresses = new Set(wallets.map((w) => w.address.toLowerCase()));
      this._walletRefreshAt = Date.now();
      this.logger.debug('BlockchainListener: wallet cache refreshed', {
        count: this._walletAddresses.size,
      });
    } catch (err) {
      this.logger.error('BlockchainListener: failed to refresh wallet addresses', {
        error: err.message,
      });
      // Don't throw — keep using stale cache rather than crash
    }
  }

  // ─── State Persistence ───────────────────────────────────────────────────────

  async _getLastScannedBlock() {
    const config = await SystemConfig.findOne({ key: 'lastScannedBlock' }).lean();
    return config ? Number(config.value) : 0;
  }

  async _setLastScannedBlock(blockNum) {
    await SystemConfig.findOneAndUpdate(
      { key: 'lastScannedBlock' },
      { key: 'lastScannedBlock', value: String(blockNum), updatedAt: new Date() },
      { upsert: true, new: true },
    );
  }

  // ─── Stale Block Detection ───────────────────────────────────────────────────

  async _checkStaleness() {
    if (!this._lastBlockTime) return;

    const staleThresholdMs = this.config.staleBlockAlertMs || 30_000;
    const ageMs = Date.now() - this._lastBlockTime;

    if (ageMs > staleThresholdMs) {
      await this._fireAlert('stale_block', {
        message: `No new block detected in ${Math.round(ageMs / 1000)}s (threshold: ${staleThresholdMs / 1000}s)`,
        lastBlockAge: ageMs,
      });
    }
  }

  // ─── Alerts ─────────────────────────────────────────────────────────────────

  async _fireAlert(type, payload) {
    try {
      await this.alertPublisher.publish(
        { type, service: 'blockchain-listener', ...payload },
        `alert:${type}:${Date.now()}`,
      );
    } catch (err) {
      // Never let alert failure crash the listener
      this.logger.error('BlockchainListener: failed to fire alert', { type, error: err.message });
    }
  }
}

module.exports = BlockchainListener;
