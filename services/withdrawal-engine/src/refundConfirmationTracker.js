'use strict';

/**
 * @module withdrawal-engine/refundConfirmationTracker
 *
 * Refund Confirmation Tracker
 *
 * Tracks 'broadcast' refunds until they reach MIN_CONFIRMATIONS.
 * When confirmed, marks the Refund completed, balances the ledger (refund_outgoing),
 * and fires the refund.completed webhook.
 */

const { Refund, LedgerEntry } = require('@xcg/database');
const { v4: uuidv4 } = require('uuid');

const POLL_INTERVAL_MS  = 30_000;  
const MIN_CONFIRMATIONS = 19;      
const MAX_POLL_ATTEMPTS = 120;     

class RefundConfirmationTracker {
  constructor({ tronAdapter, confirmedPublisher, alertPublisher, minConfirmations, logger }) {
    this.tronAdapter        = tronAdapter;
    this.confirmedPublisher = confirmedPublisher; // usually PAYMENT_CONFIRMED queue for webhook dispatch
    this.alertPublisher     = alertPublisher;
    this.minConfirmations   = minConfirmations || MIN_CONFIRMATIONS;
    this.logger             = logger;

    this._tracking  = new Map();
    this._timer     = null;
    this._running   = false;
  }

  async start() {
    this.logger.info('RefundConfirmationTracker: starting up — loading broadcast refunds');

    const broadcastList = await Refund.find({ status: 'broadcast', txHash: { $exists: true, $ne: null } })
      .select('_id refundId txHash merchantId refundAmount toAddress')
      .lean();

    for (const r of broadcastList) {
      this._tracking.set(String(r._id), { txHash: r.txHash, attempts: 0, doc: r });
    }

    if (this._tracking.size > 0) {
      this.logger.info('RefundConfirmationTracker: recovered broadcast refunds', { count: this._tracking.size });
    }

    this._running = true;
    this._timer = setInterval(() => this._poll(), POLL_INTERVAL_MS);
    this._poll().catch(() => {});
  }

  stop() {
    this._running = false;
    if (this._timer) clearInterval(this._timer);
    this.logger.info('RefundConfirmationTracker: stopped');
  }

  track(refundDocId, txHash, doc = {}) {
    if (this._tracking.has(refundDocId)) return;
    this._tracking.set(refundDocId, { txHash, attempts: 0, doc: { _id: refundDocId, txHash, ...doc } });
    this.logger.info('RefundConfirmationTracker: tracking new broadcast refund', { refundDocId, txHash });
  }

  async _poll() {
    if (!this._running || this._tracking.size === 0) return;
    const toRemove = [];

    for (const [refundDocId, entry] of this._tracking) {
      entry.attempts++;
      try {
        const confirmations = await this.tronAdapter.getConfirmations(entry.txHash);
        
        if (confirmations >= this.minConfirmations) {
          await this._markCompleted(refundDocId, entry);
          toRemove.push(refundDocId);
          continue;
        }

        if (entry.attempts >= MAX_POLL_ATTEMPTS) {
          this.logger.error('RefundConfirmationTracker: max poll attempts reached', { refundDocId, txHash: entry.txHash });
          await this._alert('refund_confirmation_timeout', {
            refundId: entry.doc.refundId || refundDocId,
            txHash: entry.txHash,
            message: `Refund ${refundDocId} broadcast but not confirmed after ${MAX_POLL_ATTEMPTS} polls.`,
          });
          toRemove.push(refundDocId);
        }
      } catch (err) {
        this.logger.warn('RefundConfirmationTracker: poll error', { refundDocId, error: err.message });
      }
    }

    for (const id of toRemove) this._tracking.delete(id);
  }

  async _markCompleted(refundDocId, entry) {
    const updated = await Refund.findOneAndUpdate(
      { _id: refundDocId, status: 'broadcast' },
      { $set: { status: 'completed', confirmedAt: new Date() } },
      { new: true }
    ).lean();

    if (!updated) return;

    this.logger.info('RefundConfirmationTracker: refund confirmed on-chain', {
      refundId: updated.refundId, txHash: entry.txHash, amount: updated.refundAmount
    });

    // Close the double-entry accounting (debit refund_outgoing)
    const idempotencyKey = `ledger:ref-settled:${updated.refundId}`;
    await LedgerEntry.create({
      entryId:        `led_${uuidv4().replace(/-/g, '')}`,
      account:        'refund_outgoing',
      type:           'debit',
      amount:         updated.refundAmount,
      currency:       updated.currency || 'USDT',
      merchantId:     updated.merchantId,
      description:    `Refund settled on-chain — txHash ${entry.txHash}`,
      idempotencyKey,
      metadata: { txHash: entry.txHash, confirmedAt: updated.confirmedAt, toAddress: updated.toAddress },
    }).catch(err => {
      if (err.code !== 11000) {
        this.logger.error('RefundConfirmationTracker: LEDGER SETTLEMENT FAILED', { refundId: updated.refundId, error: err.message });
      }
    });

    if (this.confirmedPublisher) {
      await this.confirmedPublisher.publish({
        event:       'refund.completed',
        merchantId:  String(updated.merchantId),
        refundId:    updated.refundId,
        amount:      String(updated.refundAmount),
        toAddress:   updated.toAddress,
        txHash:      entry.txHash,
        completedAt: updated.confirmedAt.toISOString(),
      }, `refund:completed:${updated.refundId}`).catch(() => {});
    }
  }

  async _alert(type, data) {
    if (!this.alertPublisher) return;
    try {
      await this.alertPublisher.publish({ type, ...data }, `alert:${type}:${Date.now()}`);
    } catch { }
  }
}

module.exports = RefundConfirmationTracker;
