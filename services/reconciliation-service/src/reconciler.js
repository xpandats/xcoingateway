'use strict';

/**
 * @module reconciliation-service/reconciler — FIXED
 *
 * FIXES:
 *   1. Balance pause flag now sets a REASON key — admin pause is never auto-cleared
 *   2. Per-wallet ledger balance (not aggregate cross all wallets)
 *   3. Auto-clear only when ALL wallets are clean AND the pause was set by reconciler,
 *      never auto-clear a manually triggered admin pause
 */

const { Wallet, LedgerEntry } = require('@xcg/database');

const RECONCILE_INTERVAL_MS      = 15 * 60 * 1000; // 15 minutes
const MISMATCH_THRESHOLD         = 0.01;            // $0.01 USDT tolerance
const PAUSE_WITHDRAWALS_KEY      = 'xcg:system:withdrawals_paused';
const PAUSE_REASON_KEY           = 'xcg:system:withdrawals_pause_reason';
const RECONCILER_PAUSE_REASON    = 'reconciliation_mismatch';

class Reconciler {
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

      let anyMismatch = false;

      for (const wallet of wallets) {
        try {
          const onChainBalance = parseFloat(await this.tronAdapter.getUSDTBalance(wallet.address));
          // FIX: per-wallet ledger balance (not aggregate across all wallets)
          const ledgerBalance  = await this._getLedgerBalanceForWallet(String(wallet._id));

          const diff = Math.abs(onChainBalance - ledgerBalance);

          if (diff > MISMATCH_THRESHOLD) {
            anyMismatch = true;
            this.logger.error('Reconciler: BALANCE MISMATCH DETECTED', {
              walletId:       String(wallet._id),
              address:        wallet.address,
              onChainBalance,
              ledgerBalance,
              diff,
            });

            // Auto-pause withdrawals (24h TTL — admin must review)
            await this.redis.set(PAUSE_WITHDRAWALS_KEY, '1', 'EX', 24 * 60 * 60);
            // Tag the reason so admin auto-clear code knows who set it
            await this.redis.set(PAUSE_REASON_KEY, RECONCILER_PAUSE_REASON, 'EX', 24 * 60 * 60);

            await this._alert('reconciliation_mismatch', {
              walletId:      String(wallet._id),
              address:       wallet.address,
              onChainBalance,
              ledgerBalance,
              diff,
              message: `CRITICAL: Ledger mismatch of ${diff.toFixed(6)} USDT on wallet ${wallet.address}. Withdrawals auto-paused.`,
            });
          } else {
            this.logger.info('Reconciler: wallet OK', {
              address: wallet.address, onChainBalance, ledgerBalance, diff,
            });
          }
        } catch (err) {
          this.logger.error('Reconciler: failed to check wallet', {
            address: wallet.address, error: err.message,
          });
        }
      }

      if (!anyMismatch) {
        // FIX: Only clear pause if it was set by THIS reconciler, not by admin
        const pauseReason = await this.redis.get(PAUSE_REASON_KEY);
        if (pauseReason === RECONCILER_PAUSE_REASON) {
          await this.redis.del(PAUSE_WITHDRAWALS_KEY);
          await this.redis.del(PAUSE_REASON_KEY);
          this.logger.info('Reconciler: all wallets balanced — withdrawal pause lifted');
        } else if (pauseReason) {
          this.logger.info('Reconciler: all wallets balanced — pause kept (set by admin)');
        }
        this.logger.info('Reconciler: cycle complete');
      }

    } catch (err) {
      this.logger.error('Reconciler: cycle failed', { error: err.message });
    }
  }

  /**
   * FIX: Compute ledger balance per wallet using invoices linked to that wallet.
   * Compare on-chain balance against ALL receivable credits minus debits for that wallet's invoices.
   */
  async _getLedgerBalanceForWallet(walletId) {
    // Get all invoices for this specific wallet
    const { Invoice } = require('@xcg/database');
    const invoiceIds = await Invoice.find({ walletId }).select('_id').lean()
      .then((list) => list.map((i) => i._id));

    if (invoiceIds.length === 0) return 0;

    const result = await LedgerEntry.aggregate([
      {
        $match: {
          account:   'merchant_receivable',
          invoiceId: { $in: invoiceIds },
        },
      },
      {
        $group: {
          _id:     null,
          credits: { $sum: { $cond: [{ $eq: ['$type', 'credit'] }, '$amount', 0] } },
          debits:  { $sum: { $cond: [{ $eq: ['$type', 'debit'] }, '$amount', 0] } },
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
