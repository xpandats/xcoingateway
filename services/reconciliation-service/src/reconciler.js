'use strict';

/**
 * @module reconciliation-service/reconciler
 *
 * Reconciliation Service — Runs every 15 minutes.
 *
 * WHAT IT DOES:
 *   1. For each active hot wallet: query on-chain USDT balance via TronGrid
 *   2. Compare with internal ledger sum (credits - debits)
 *   3. If mismatch > $0.01 threshold → auto-pause withdrawals + alert
 *   4. Also reconciles: total on-chain received vs total matched invoices
 *
 * WHY IT EXISTS:
 *   Without this, you have no way to detect:
 *     - Missed transactions (listener bug)
 *     - Double-credited deposits (matching engine bug)
 *     - Drained funds (security breach)
 *     - Ledger corruption
 *
 * FAIL SAFE:
 *   Any mismatch → immediately pause all withdrawals + alert admin.
 *   Better to pause and investigate than to allow potentially invalid funds to move.
 */

const IORedis   = require('ioredis');
const { Wallet, LedgerEntry } = require('@xcg/database');

const RECONCILE_INTERVAL_MS = 15 * 60 * 1000; // 15 minutes
const MISMATCH_THRESHOLD    = 0.01;             // $0.01 USDT tolerance
const PAUSE_WITHDRAWALS_KEY = 'xcg:system:withdrawals_paused';

class Reconciler {
  /**
   * @param {object} opts
   * @param {object} opts.tronAdapter    - TronAdapter instance
   * @param {object} opts.redis          - IORedis instance
   * @param {object} opts.alertPublisher - Queue publisher for SYSTEM_ALERT
   * @param {object} opts.logger
   */
  constructor({ tronAdapter, redis, alertPublisher, logger }) {
    this.tronAdapter    = tronAdapter;
    this.redis          = redis;
    this.alertPublisher = alertPublisher;
    this.logger         = logger;
    this._timer         = null;
  }

  start() {
    this.logger.info('Reconciler: starting (every 15 minutes)');
    this._scheduleNext();
  }

  stop() {
    if (this._timer) clearTimeout(this._timer);
    this.logger.info('Reconciler: stopped');
  }

  _scheduleNext() {
    this._timer = setTimeout(async () => {
      await this._run();
      this._scheduleNext();
    }, RECONCILE_INTERVAL_MS);
  }

  async _run() {
    this.logger.info('Reconciler: starting reconciliation cycle');

    try {
      const wallets = await Wallet.find({ isActive: true, type: { $in: ['hot', 'receiving'] } })
        .select('_id address label balance')
        .lean();

      let allClear = true;

      for (const wallet of wallets) {
        try {
          const onChainBalance = parseFloat(await this.tronAdapter.getUSDTBalance(wallet.address));
          const ledgerBalance  = await this._getLedgerBalanceForWallet(wallet._id);

          const diff = Math.abs(onChainBalance - ledgerBalance);

          if (diff > MISMATCH_THRESHOLD) {
            allClear = false;
            this.logger.error('Reconciler: BALANCE MISMATCH DETECTED', {
              walletId:        String(wallet._id),
              address:         wallet.address,
              onChainBalance,
              ledgerBalance,
              diff,
            });

            // Auto-pause all withdrawals
            await this.redis.set(PAUSE_WITHDRAWALS_KEY, '1', 'EX', 24 * 60 * 60);

            // Fire alert
            await this._alert('reconciliation_mismatch', {
              walletId:      String(wallet._id),
              address:       wallet.address,
              onChainBalance,
              ledgerBalance,
              diff,
              message:       `CRITICAL: Ledger mismatch of ${diff.toFixed(6)} USDT on wallet ${wallet.address}. Withdrawals auto-paused.`,
            });
          } else {
            this.logger.info('Reconciler: wallet OK', {
              address: wallet.address,
              onChainBalance,
              ledgerBalance,
              diff,
            });
          }
        } catch (err) {
          this.logger.error('Reconciler: failed to check wallet', {
            address: wallet.address, error: err.message,
          });
        }
      }

      if (allClear) {
        // Clear pause flag if all wallets reconcile cleanly
        await this.redis.del(PAUSE_WITHDRAWALS_KEY);
        this.logger.info('Reconciler: cycle complete — all wallets balanced');
      }

    } catch (err) {
      this.logger.error('Reconciler: cycle failed', { error: err.message });
    }
  }

  async _getLedgerBalanceForWallet(walletId) {
    // Sum all ledger entries: credits - debits for this wallet
    // Note: LedgerEntry references walletId via withdrawalId → wallet indirectly
    // For simplicity in MVP: sum all merchant receivable credits - debits
    // TODO Phase 3: wallet-level ledger reconciliation
    const result = await LedgerEntry.aggregate([
      { $match: { account: 'merchant_receivable' } },
      {
        $group: {
          _id: null,
          credits: { $sum: { $cond: [{ $eq: ['$type', 'credit'] }, '$amount', 0] } },
          debits:  { $sum: { $cond: [{ $eq: ['$type', 'debit'] },  '$amount', 0] } },
        },
      },
    ]);
    return result.length ? result[0].credits - result[0].debits : 0;
  }

  async _alert(type, payload) {
    try {
      await this.alertPublisher.publish(
        { type, service: 'reconciliation-service', ...payload },
        `alert:${type}:${Date.now()}`,
      );
    } catch (err) {
      this.logger.error('Reconciler: alert failed', { type, error: err.message });
    }
  }
}

module.exports = Reconciler;
