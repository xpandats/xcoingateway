'use strict';

/**
 * @module withdrawal-engine/withdrawalConfirmationTracker
 *
 * Withdrawal Confirmation Tracker
 *
 * PROBLEM:
 *   After the signing service broadcasts a withdrawal on-chain, the withdrawal
 *   status is set to 'broadcast'. There is no mechanism to:
 *     1. Detect when the Tron network confirms the transaction
 *     2. Update the withdrawal status to 'completed'
 *     3. Fire a withdrawal.completed webhook to the merchant
 *
 * SOLUTION:
 *   A background tracker that:
 *     - On startup: loads all 'broadcast' withdrawals from DB (crash recovery)
 *     - Every 30 seconds: polls Tron for confirmation count of each tracked txHash
 *     - On >= MIN_CONFIRMATIONS: updates withdrawal → 'completed' + fires webhook event
 *     - Removes from tracking set once confirmed (or after MAX_POLL_ATTEMPTS)
 *
 * FLOW:
 *   signing:complete consumer sets status='broadcast' + txHash
 *   → WithdrawalConfirmationTracker.track(withdrawalId, txHash)
 *   → Polls TronAdapter.getConfirmations(txHash) every POLL_INTERVAL_MS
 *   → On confirmed: Withdrawal.status = 'completed', publish withdrawal.completed event
 *
 * SAFETY:
 *   - Idempotent: update uses $set + only changes if current status is 'broadcast'
 *   - Max attempts: prevents infinite polling if tx is dropped or orphaned
 *   - Alerts on failure: operator is notified if a withdrawal cannot be confirmed
 */

const { Withdrawal, LedgerEntry } = require('@xcg/database');
const { v4: uuidv4 } = require('uuid');

const POLL_INTERVAL_MS  = 30_000;  // Poll every 30 seconds
const MIN_CONFIRMATIONS = 19;      // Same as inbound payment requirement (Tron spec)
const MAX_POLL_ATTEMPTS = 120;     // Max 1 hour total (120 × 30s = 60 min)

class WithdrawalConfirmationTracker {
  /**
   * @param {object} opts
   * @param {object} opts.tronAdapter           - TronAdapter instance
   * @param {object} opts.confirmedPublisher    - Publisher for withdrawal.completed events
   * @param {object} opts.alertPublisher        - Publisher for SYSTEM_ALERT events
   * @param {number} [opts.minConfirmations]    - Override minimum confirmations
   * @param {object} opts.logger
   */
  constructor({ tronAdapter, confirmedPublisher, alertPublisher, minConfirmations, logger }) {
    this.tronAdapter        = tronAdapter;
    this.confirmedPublisher = confirmedPublisher;
    this.alertPublisher     = alertPublisher;
    this.minConfirmations   = minConfirmations || MIN_CONFIRMATIONS;
    this.logger             = logger;

    // Map of withdrawalId → { txHash, attempts, withdrawalId (string) }
    this._tracking  = new Map();
    this._timer     = null;
    this._running   = false;
  }

  /**
   * Start the tracker.
   * Loads all 'broadcast' withdrawals from DB (crash recovery on restart).
   */
  async start() {
    this.logger.info('WithdrawalConfirmationTracker: starting up — loading broadcast withdrawals');

    // Crash recovery: any withdrawal in 'broadcast' status that survived a restart
    const broadcastList = await Withdrawal.find({ status: 'broadcast', txHash: { $exists: true, $ne: null } })
      .select('_id withdrawalId txHash merchantId amount toAddress')
      .lean();

    for (const w of broadcastList) {
      this._tracking.set(String(w._id), { txHash: w.txHash, attempts: 0, doc: w });
    }

    if (this._tracking.size > 0) {
      this.logger.info('WithdrawalConfirmationTracker: recovered broadcast withdrawals', {
        count: this._tracking.size,
      });
    }

    this._running = true;
    this._timer = setInterval(() => this._poll(), POLL_INTERVAL_MS);

    // Immediate first poll
    this._poll().catch((err) => this.logger.error('WithdrawalConfirmationTracker: first poll failed', { error: err.message }));
  }

  /**
   * Stop the tracker gracefully.
   */
  stop() {
    this._running = false;
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
    this.logger.info('WithdrawalConfirmationTracker: stopped');
  }

  /**
   * Add a newly broadcast withdrawal to the tracking set.
   * Called by the signing:complete consumer in server.js.
   *
   * @param {string} withdrawalId   - Mongoose _id string
   * @param {string} txHash         - On-chain transaction hash
   * @param {object} doc            - Partial withdrawal doc { withdrawalId, merchantId, amount, toAddress }
   */
  track(withdrawalId, txHash, doc = {}) {
    if (this._tracking.has(withdrawalId)) return; // Already tracking
    this._tracking.set(withdrawalId, { txHash, attempts: 0, doc: { _id: withdrawalId, txHash, ...doc } });
    this.logger.info('WithdrawalConfirmationTracker: tracking new broadcast withdrawal', {
      withdrawalId, txHash,
    });
  }

  /**
   * Internal poll — runs every POLL_INTERVAL_MS.
   * Checks confirmation count for each tracked withdrawal.
   */
  async _poll() {
    if (!this._running || this._tracking.size === 0) return;

    const toRemove = [];

    for (const [withdrawalId, entry] of this._tracking) {
      entry.attempts++;

      try {
        const confirmations = await this.tronAdapter.getConfirmations(entry.txHash);

        this.logger.debug('WithdrawalConfirmationTracker: polled', {
          withdrawalId, txHash: entry.txHash, confirmations, attempt: entry.attempts,
        });

        if (confirmations >= this.minConfirmations) {
          await this._markCompleted(withdrawalId, entry);
          toRemove.push(withdrawalId);
          continue;
        }

        if (entry.attempts >= MAX_POLL_ATTEMPTS) {
          this.logger.error('WithdrawalConfirmationTracker: max poll attempts reached — manual review required', {
            withdrawalId, txHash: entry.txHash, attempts: entry.attempts,
          });
          await this._alert('withdrawal_confirmation_timeout', {
            withdrawalId: entry.doc.withdrawalId || withdrawalId,
            txHash: entry.txHash,
            message: `Withdrawal ${withdrawalId} broadcast but not confirmed after ${MAX_POLL_ATTEMPTS} polls. Manual review required.`,
          });
          toRemove.push(withdrawalId);
        }

      } catch (err) {
        this.logger.warn('WithdrawalConfirmationTracker: poll error', {
          withdrawalId, txHash: entry.txHash, error: err.message, attempt: entry.attempts,
        });
        // Don't remove — retry on next poll cycle
      }
    }

    for (const id of toRemove) {
      this._tracking.delete(id);
    }
  }

  /**
   * Mark a withdrawal as completed, post the final ledger entry, and fire webhook.
   *
   * DOUBLE-ENTRY ACCOUNTING:
   *   At withdrawal creation (processor.js), we post:
   *     DEBIT  merchant_receivable   (reduces what merchant is owed)
   *     CREDIT merchant_withdrawal   (liability — funds in transit to merchant)
   *
   *   On on-chain confirmation HERE, we complete the second leg:
   *     DEBIT  merchant_withdrawal   (liability settled — funds left the platform)
   *
   *   This makes the ledger balance: debits = credits at all times.
   *   Without this entry, reconciliation reports always show a discrepancy.
   */
  async _markCompleted(withdrawalId, entry) {
    // Atomic update: only change if still 'broadcast' — prevents double-completion
    const updated = await Withdrawal.findOneAndUpdate(
      { _id: withdrawalId, status: 'broadcast' },
      {
        $set: {
          status:      'completed',
          confirmedAt: new Date(),
        },
      },
      { new: true },
    ).lean();

    if (!updated) {
      // Already completed by another process (idempotent — skip)
      this.logger.info('WithdrawalConfirmationTracker: withdrawal already completed (skipping)', { withdrawalId });
      return;
    }

    this.logger.info('WithdrawalConfirmationTracker: withdrawal confirmed on-chain', {
      withdrawalId:  updated.withdrawalId,
      txHash:        entry.txHash,
      merchantId:    String(updated.merchantId),
      amount:        updated.amount,
    });

    // ── Post final ledger entry: DEBIT merchant_withdrawal ─────────────────────
    // This closes the double-entry cycle opened by the withdrawal processor.
    // Idempotency key prevents duplicate entry if this method is somehow called twice.
    const idempotencyKey = `ledger:wdl-settled:${updated.withdrawalId}`;
    await LedgerEntry.create({
      entryId:        `led_${uuidv4().replace(/-/g, '')}`,
      account:        'merchant_withdrawal',
      type:           'debit',
      amount:         updated.amount,
      currency:       'USDT',
      merchantId:     updated.merchantId,
      withdrawalId:   updated._id,
      description:    `Withdrawal settled on-chain — txHash ${entry.txHash}`,
      idempotencyKey,
      metadata: {
        txHash:      entry.txHash,
        confirmedAt: updated.confirmedAt,
        toAddress:   updated.toAddress,
      },
    }).catch((err) => {
      // On duplicate key (idempotent re-run) — log and continue, do NOT block webhook
      if (err.code === 11000) {
        this.logger.info('WithdrawalConfirmationTracker: ledger settlement entry already exists (idempotent)', { withdrawalId });
      } else {
        // Non-idempotency DB error: log loudly but do NOT throw — webhook must still fire
        this.logger.error('WithdrawalConfirmationTracker: LEDGER SETTLEMENT FAILED — manual correction required', {
          withdrawalId:  updated.withdrawalId,
          txHash:        entry.txHash,
          amount:        updated.amount,
          error:         err.message,
        });
      }
    });

    // Fire withdrawal.completed event to notification service (→ merchant webhook)
    if (this.confirmedPublisher) {
      await this.confirmedPublisher.publish(
        {
          event:        'withdrawal.completed',
          merchantId:   String(updated.merchantId),
          withdrawalId: updated.withdrawalId,
          amount:       String(updated.amount),
          toAddress:    updated.toAddress,
          txHash:       entry.txHash,
          completedAt:  updated.confirmedAt.toISOString(),
        },
        `withdrawal:completed:${updated.withdrawalId}`,
      ).catch((err) => this.logger.error('WithdrawalConfirmationTracker: failed to publish completed event', {
        withdrawalId, error: err.message,
      }));
    }
  }

  async _alert(type, data) {
    if (!this.alertPublisher) return;
    try {
      await this.alertPublisher.publish({ type, ...data }, `alert:${type}:${Date.now()}`);
    } catch (err) {
      this.logger.error('WithdrawalConfirmationTracker: failed to publish alert', { error: err.message });
    }
  }
}

module.exports = WithdrawalConfirmationTracker;
