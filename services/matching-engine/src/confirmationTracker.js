'use strict';

/**
 * @module matching-engine/confirmationTracker
 *
 * Confirmation Tracker — Phase 2 Completion.
 *
 * PROBLEM SOLVED:
 *   The blockchain listener publishes each tx ONCE (dedup by txHash).
 *   If the tx has < 19 confirmations at publish time, the matching engine
 *   discards it and it is NEVER retried. Payments are stuck in hash_found.
 *
 * SOLUTION:
 *   A separate polling loop runs every POLL_INTERVAL_MS and:
 *   1. Finds all Transaction records in TX_STATUS.DETECTED with < required confirmations
 *   2. Queries TronAdapter for the current confirmation count of each pending tx
 *   3. Once confirmations >= minConfirmations → calls engine._confirmPayment()
 *   4. Implements stuck-transaction recovery on startup
 *
 * STATE MACHINE (now complete):
 *   PENDING → HASH_FOUND (on first detection)
 *   HASH_FOUND → CONFIRMING (engine sets immediately on receipt)
 *   CONFIRMING → CONFIRMED (this tracker completes the confirmation)
 *
 * INVARIANTS:
 *   - Only processes TX_STATUS.DETECTED (= awaiting confirmations)
 *   - Batch size capped at 50 to prevent overload
 *   - Each tx is checked at most once per poll cycle
 *   - Memory-safe: no in-memory state — reloads from DB each cycle
 */

const { Transaction, Invoice } = require('@xcg/database');
const { TX_STATUS, INVOICE_STATUS, TRON } = require('@xcg/common').constants;

const POLL_INTERVAL_MS = 10_000; // Check every 10 seconds
const MAX_BATCH_SIZE   = 50;     // Max pending txs per cycle
const MAX_AGE_HOURS    = 6;      // Give up after 6 hours (tx will never complete)

class ConfirmationTracker {
  /**
   * @param {object} opts
   * @param {object} opts.adapter         - TronAdapter instance (to query confirmation count)
   * @param {object} opts.engine          - MatchingEngine instance (to call _confirmPayment)
   * @param {object} opts.alertPublisher  - Queue publisher for SYSTEM_ALERT
   * @param {number} opts.minConfirmations
   * @param {object} opts.logger
   */
  constructor({ adapter, engine, alertPublisher, minConfirmations, logger }) {
    this.adapter          = adapter;
    this.engine           = engine;
    this.alertPublisher   = alertPublisher;
    this.minConfirmations = minConfirmations || TRON.CONFIRMATIONS_REQUIRED;
    this.logger           = logger;
    this._running         = false;
    this._timer           = null;
  }

  // ─── Lifecycle ──────────────────────────────────────────────────────────────

  async start() {
    this.logger.info('ConfirmationTracker: starting');
    this._running = true;

    // Run stuck-tx recovery immediately on startup
    await this._recoverStuckTransactions();

    // Schedule first poll
    this._scheduleNext(0);
    this.logger.info(`ConfirmationTracker: running — poll every ${POLL_INTERVAL_MS / 1000}s`);
  }

  stop() {
    this._running = false;
    if (this._timer) clearTimeout(this._timer);
    this.logger.info('ConfirmationTracker: stopped');
  }

  _scheduleNext(delay) {
    if (!this._running) return;
    this._timer = setTimeout(() => this._poll(), delay);
  }

  // ─── Startup: Stuck Transaction Recovery ─────────────────────────────────────

  /**
   * On boot: find all transactions that were awaiting confirmations when
   * the service last crashed/restarted. Re-enqueue them for confirmation
   * polling so no payments are permanently stuck.
   */
  async _recoverStuckTransactions() {
    try {
      const stuckCount = await Transaction.countDocuments({ status: TX_STATUS.DETECTED });
      if (stuckCount === 0) {
        this.logger.info('ConfirmationTracker: no stuck transactions found on startup');
        return;
      }

      this.logger.warn('ConfirmationTracker: found stuck transactions on startup — recovering', {
        count: stuckCount,
      });

      // Fire admin alert for visibility
      await this._fireAlert('stuck_transactions_recovery', {
        message: `ConfirmationTracker: recovering ${stuckCount} stuck transactions on startup`,
        count: stuckCount,
      });

    } catch (err) {
      this.logger.error('ConfirmationTracker: startup recovery check failed', { error: err.message });
    }
  }

  // ─── Main Poll Cycle ─────────────────────────────────────────────────────────

  async _poll() {
    try {
      await this._checkPendingConfirmations();
    } catch (err) {
      this.logger.error('ConfirmationTracker: poll error', { error: err.message });
    } finally {
      this._scheduleNext(POLL_INTERVAL_MS);
    }
  }

  async _checkPendingConfirmations() {
    const maxAgeDate = new Date(Date.now() - MAX_AGE_HOURS * 3600_000);

    // Load all DETECTED transactions (awaiting confirmations), most recent first
    // Exclude very old ones that are likely lost on-chain
    const pendingTxs = await Transaction.find({
      status:    TX_STATUS.DETECTED,
      detectedAt:{ $gte: maxAgeDate },
    })
      .sort({ detectedAt: 1 }) // Oldest first — process in order
      .limit(MAX_BATCH_SIZE)
      .lean();

    if (pendingTxs.length === 0) return;

    this.logger.debug('ConfirmationTracker: checking pending transactions', {
      count: pendingTxs.length,
    });

    // Process each pending tx
    for (const tx of pendingTxs) {
      await this._checkTransaction(tx);
    }
  }

  async _checkTransaction(tx) {
    try {
      // Query current block height from Tron to compute confirmations
      let currentConfirmations = tx.confirmations;

      try {
        // Get latest block from adapter and compute delta from tx block
        const latestBlock = await this.adapter.getLatestBlock();
        currentConfirmations = latestBlock - tx.blockNumber;
      } catch (adapterErr) {
        // Adapter failure: use last known confirmations (non-fatal)
        this.logger.warn('ConfirmationTracker: failed to fetch latest block', {
          txHash: tx.txHash, error: adapterErr.message,
        });
      }

      this.logger.debug('ConfirmationTracker: tx confirmation status', {
        txHash:    tx.txHash,
        have:      currentConfirmations,
        need:      this.minConfirmations,
        blockNum:  tx.blockNumber,
      });

      if (currentConfirmations < this.minConfirmations) {
        // Not enough confirmations yet — update count in DB and continue waiting
        await Transaction.updateOne(
          { _id: tx._id, status: TX_STATUS.DETECTED },
          { $set: { confirmations: currentConfirmations } },
        );
        return;
      }

      // ✅ ENOUGH CONFIRMATIONS — build txData and confirm the payment
      this.logger.info('ConfirmationTracker: tx fully confirmed — triggering payment confirmation', {
        txHash: tx.txHash, confirmations: currentConfirmations,
      });

      await this._triggerConfirmation(tx, currentConfirmations);

    } catch (err) {
      this.logger.error('ConfirmationTracker: error checking transaction', {
        txHash: tx.txHash, error: err.message,
      });

      // Increment attempt counter on error
      await Transaction.updateOne(
        { _id: tx._id },
        { $inc: { processingAttempts: 1 }, $set: { lastError: err.message } },
      ).catch(() => {});
    }
  }

  async _triggerConfirmation(tx, currentConfirmations) {
    // Find the linked invoice
    const invoice = await Invoice.findOne({
      walletAddress: tx.toAddress,
      uniqueAmount:  tx.amount,
      status:        { $in: [INVOICE_STATUS.HASH_FOUND, INVOICE_STATUS.PENDING] },
    }).lean();

    if (!invoice) {
      this.logger.warn('ConfirmationTracker: no matching invoice for confirmed tx', {
        txHash: tx.txHash, toAddress: tx.toAddress, amount: tx.amount,
      });

      // Mark tx as unmatched and stop polling it
      await Transaction.updateOne(
        { _id: tx._id, status: TX_STATUS.DETECTED },
        { $set: { status: TX_STATUS.UNMATCHED, processedAt: new Date() } },
      );
      return;
    }

    // Build the txData payload for the engine
    const txData = {
      txHash:        tx.txHash,
      blockNum:      tx.blockNumber,
      blockNumber:   tx.blockNumber,
      confirmations: currentConfirmations,
      fromAddress:   tx.fromAddress,
      toAddress:     tx.toAddress,
      amount:        String(tx.amount),
      tokenContract: tx.tokenContract,
      tokenSymbol:   tx.tokenSymbol || 'USDT',
      network:       tx.network || 'tron',
      timestamp:     tx.blockTimestamp ? Math.floor(new Date(tx.blockTimestamp).getTime() / 1000) : null,
      detectedAt:    tx.detectedAt ? new Date(tx.detectedAt).getTime() : Date.now(),
    };

    // Mark TX as MATCHED (confirmed status) BEFORE calling engine
    // This prevents duplicate confirmation if something loops
    const claimed = await Transaction.findOneAndUpdate(
      { _id: tx._id, status: TX_STATUS.DETECTED },
      { $set: { status: TX_STATUS.MATCHED, confirmations: currentConfirmations, processedAt: new Date() } },
    );

    if (!claimed) {
      // Another process already claimed this tx (race condition)
      this.logger.warn('ConfirmationTracker: tx already claimed by another process', { txHash: tx.txHash });
      return;
    }

    // Run the payment confirmation
    await this.engine._confirmPayment(txData, invoice);
  }

  // ─── Alert Helper ─────────────────────────────────────────────────────────────

  async _fireAlert(type, payload) {
    try {
      await this.alertPublisher.publish(
        { type, service: 'confirmation-tracker', ...payload },
        `alert:${type}:${Date.now()}`,
      );
    } catch { /* never crash tracker */ }
  }
}

module.exports = ConfirmationTracker;
