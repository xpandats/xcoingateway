'use strict';

/**
 * @module withdrawal-engine/transferConfirmationTracker
 *
 * Wallet Transfer Confirmation Tracker
 */

const { WalletTransfer, LedgerEntry } = require('@xcg/database');
const { v4: uuidv4 } = require('uuid');

const POLL_INTERVAL_MS  = 30_000;
const MIN_CONFIRMATIONS = 19;
const MAX_POLL_ATTEMPTS = 120;

class TransferConfirmationTracker {
  constructor({ tronAdapter, alertPublisher, minConfirmations, logger }) {
    this.tronAdapter      = tronAdapter;
    this.alertPublisher   = alertPublisher;
    this.minConfirmations = minConfirmations || MIN_CONFIRMATIONS;
    this.logger           = logger;

    this._tracking  = new Map();
    this._timer     = null;
    this._running   = false;
  }

  async start() {
    this.logger.info('TransferConfirmationTracker: starting up');
    const broadcastList = await WalletTransfer.find({ status: 'broadcast', txHash: { $exists: true, $ne: null } })
      .select('_id transferId txHash amount toAddress transferType token')
      .lean();

    for (const t of broadcastList) {
      this._tracking.set(String(t._id), { txHash: t.txHash, attempts: 0, doc: t });
    }
    this._running = true;
    this._timer = setInterval(() => this._poll(), POLL_INTERVAL_MS);
    this._poll().catch(() => {});
  }

  stop() {
    this._running = false;
    if (this._timer) clearInterval(this._timer);
  }

  track(transferDocId, txHash, doc = {}) {
    if (this._tracking.has(transferDocId)) return;
    this._tracking.set(transferDocId, { txHash, attempts: 0, doc: { _id: transferDocId, txHash, ...doc } });
    this.logger.info('TransferConfirmationTracker: tracking new broadcast transfer', { transferDocId, txHash });
  }

  async _poll() {
    if (!this._running || this._tracking.size === 0) return;
    const toRemove = [];

    for (const [transferDocId, entry] of this._tracking) {
      entry.attempts++;
      try {
        const confirmations = await this.tronAdapter.getConfirmations(entry.txHash);
        
        if (confirmations >= this.minConfirmations) {
          await this._markCompleted(transferDocId, entry);
          toRemove.push(transferDocId);
          continue;
        }

        if (entry.attempts >= MAX_POLL_ATTEMPTS) {
          this.logger.error('TransferConfirmationTracker: max poll attempts reached', { transferDocId, txHash: entry.txHash });
          toRemove.push(transferDocId);
        }
      } catch (err) {
        this.logger.warn('TransferConfirmationTracker: poll error', { transferDocId, error: err.message });
      }
    }

    for (const id of toRemove) this._tracking.delete(id);
  }

  async _markCompleted(transferDocId, entry) {
    const updated = await WalletTransfer.findOneAndUpdate(
      { _id: transferDocId, status: 'broadcast' },
      { $set: { status: 'completed', confirmedAt: new Date() } },
      { new: true }
    ).lean();

    if (!updated) return;

    this.logger.info('TransferConfirmationTracker: transfer confirmed on-chain', {
      transferId: updated.transferId, txHash: entry.txHash, amount: updated.amount
    });

    // Close double-entry for internal transfers (debit internal_transfer_incoming)
    const idempotencyKey = `ledger:trf-settled:${updated.transferId}`;
    await LedgerEntry.create({
      entryId:        `led_${uuidv4().replace(/-/g, '')}`,
      account:        'internal_transfer_incoming', // asset realized
      type:           'debit',
      amount:         updated.amount,
      currency:       updated.token || 'USDT',
      description:    `Transfer settled on-chain — txHash ${entry.txHash}`,
      idempotencyKey,
    }).catch(() => {});
  }
}

module.exports = TransferConfirmationTracker;
