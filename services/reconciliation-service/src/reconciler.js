'use strict';

/**
 * @module reconciliation-service/reconciler
 *
 * Reconciliation Runner — Compares on-chain wallet balances against the internal ledger.
 *
 * BEHAVIOUR:
 *   Scheduled: runs every 15 minutes automatically.
 *   Manual:    responds to Redis pub/sub on 'xcg:reconciliation:trigger'.
 *
 * AUDIT TRAIL:
 *   Every run creates a ReconciliationReport document (status: running → completed/failed).
 *   On mismatch: withdrawals auto-paused, admin alerted.
 *   On clean sweep: reconciler-set pause is lifted (admin-set pauses are preserved).
 *
 * SECURITY:
 *   Only clears its own pause flag (RECONCILER_PAUSE_REASON), never an admin-set pause.
 */

const { v4: uuidv4 }  = require('uuid');
const { Wallet, LedgerEntry, ReconciliationReport, MerchantBalance } = require('@xcg/database');

const RECONCILE_INTERVAL_MS   = 15 * 60 * 1000; // 15 minutes
const MISMATCH_THRESHOLD      = 0.01;            // $0.01 USDT tolerance
const PAUSE_WITHDRAWALS_KEY   = 'xcg:system:withdrawals_paused';
const PAUSE_REASON_KEY        = 'xcg:system:withdrawals_pause_reason';
const RECONCILER_PAUSE_REASON = 'reconciliation_mismatch';
const TRIGGER_CHANNEL         = 'xcg:reconciliation:trigger';

class Reconciler {
  /**
   * @param {object} opts
   * @param {object} opts.tronAdapter      - @xcg/tron TronAdapter
   * @param {object} opts.redis            - ioredis client (for read/write operations)
   * @param {object} opts.redisSub         - ioredis client dedicated to subscribe (never reuse pub connection)
   * @param {object} opts.alertPublisher   - @xcg/queue publisher for SYSTEM_ALERT
   * @param {object} opts.logger
   */
  constructor({ tronAdapter, redis, redisSub, alertPublisher, logger }) {
    this.tronAdapter    = tronAdapter;
    this.redis          = redis;
    this.redisSub       = redisSub;       // Separate connection for subscribe()
    this.alertPublisher = alertPublisher;
    this.logger         = logger;
    this._timer         = null;
    this._running       = false;          // Prevent overlapping runs
  }

  /**
   * Start the scheduled reconciler and subscribe to the manual trigger channel.
   */
  start() {
    this.logger.info('Reconciler: starting (every 15 minutes)');
    this._scheduleNext();
    this._subscribeToManualTrigger();
  }

  stop() {
    if (this._timer) clearTimeout(this._timer);
    if (this.redisSub) this.redisSub.unsubscribe().catch(() => {});
    this.logger.info('Reconciler: stopped');
  }

  // ─── Schedule ──────────────────────────────────────────────────────────────

  _scheduleNext() {
    this._timer = setTimeout(async () => {
      await this._runWithReport({ triggeredBy: 'scheduler' });
      this._scheduleNext();
    }, RECONCILE_INTERVAL_MS);
  }

  // ─── Manual trigger via Redis pub/sub ──────────────────────────────────────

  _subscribeToManualTrigger() {
    if (!this.redisSub) return;

    this.redisSub.subscribe(TRIGGER_CHANNEL, (err) => {
      if (err) {
        this.logger.error('Reconciler: failed to subscribe to trigger channel', { error: err.message });
        return;
      }
      this.logger.info(`Reconciler: subscribed to ${TRIGGER_CHANNEL} — manual trigger ready`);
    });

    this.redisSub.on('message', async (channel, message) => {
      if (channel !== TRIGGER_CHANNEL) return;

      let payload = {};
      try { payload = JSON.parse(message); } catch { /* ignore malformed */ }

      this.logger.info('Reconciler: manual trigger received', { triggeredBy: payload.triggeredBy });

      // Run using the pre-created reportId from the API controller (or create fresh one)
      await this._runWithReport({
        triggeredBy: payload.triggeredBy || 'manual',
        existingReportId: payload.reportId || null,
      });
    });
  }

  // ─── Core Run ──────────────────────────────────────────────────────────────

  /**
   * Wrapper that creates/updates a ReconciliationReport record around the core run.
   * Prevents overlapping runs.
   */
  async _runWithReport({ triggeredBy, existingReportId = null }) {
    if (this._running) {
      this.logger.warn('Reconciler: run already in progress — skipping overlap');
      return;
    }

    this._running = true;

    // ── Create or find the ReconciliationReport row ────────────────────────
    let report;
    const startedAt = new Date();

    try {
      if (existingReportId) {
        // Manual trigger: the API controller already created the row
        report = await ReconciliationReport.findOne({ reportId: existingReportId });
        if (!report) {
          // Controller row not found — create fresh (safety fallback)
          this.logger.warn('Reconciler: manual trigger reportId not found in DB — creating new report', { existingReportId });
          report = await ReconciliationReport.create({
            reportId:    existingReportId,
            triggeredBy,
            startedAt,
            status:      'running',
          });
        }
      } else {
        // Scheduled run: create a new report
        report = await ReconciliationReport.create({
          reportId:    `recon_${uuidv4().replace(/-/g, '')}`,
          triggeredBy,
          startedAt,
          status:      'running',
        });
      }
    } catch (err) {
      this.logger.error('Reconciler: failed to create ReconciliationReport', { error: err.message });
      this._running = false;
      return;
    }

    // ── Run the core logic ─────────────────────────────────────────────────
    try {
      const result = await this._run(report);

      // Update report to completed
      const completedAt = new Date();
      await ReconciliationReport.findByIdAndUpdate(report._id, {
        $set: {
          status:               'completed',
          completedAt,
          durationMs:           completedAt - startedAt,
          passed:               result.passed,
          walletsChecked:       result.walletsChecked,
          mismatchCount:        result.mismatches.length,
          onChainTotalUsdt:     result.onChainTotal,
          ledgerTotalUsdt:      result.ledgerTotal,
          totalDifference:      result.totalDiff,
          mismatches:           result.mismatches,
          withdrawalsPaused:    result.pausedWithdrawals,
          alertSent:            result.alertSent,
        },
      });

      this.logger.info('Reconciler: run completed', {
        reportId:  report.reportId,
        passed:    result.passed,
        mismatches: result.mismatches.length,
        durationMs: completedAt - startedAt,
      });

    } catch (err) {
      this.logger.error('Reconciler: run failed', { reportId: report.reportId, error: err.message });

      await ReconciliationReport.findByIdAndUpdate(report._id, {
        $set: {
          status:      'failed',
          completedAt: new Date(),
          durationMs:  Date.now() - startedAt,
          error:       err.message,
          passed:      false,
        },
      }).catch(() => {}); // Never let DB update failure mask the original error
    } finally {
      this._running = false;
    }
  }

  /**
   * Core reconciliation logic — checks every active hot/receiving wallet.
   * Returns a result object for the report.
   */
  async _run(report) {
    this.logger.info('Reconciler: starting wallet reconciliation cycle', { reportId: report.reportId });

    const wallets = await Wallet.find({ isActive: true, type: { $in: ['hot', 'receiving'] } })
      .select('_id address label balance')
      .lean();

    let anyMismatch     = false;
    let pausedWithdrawals = false;
    let alertSent       = false;
    let onChainTotal    = 0;
    let ledgerTotal     = 0;
    const mismatches    = [];

    for (const wallet of wallets) {
      try {
        const onChainBalance = parseFloat(await this.tronAdapter.getUSDTBalance(wallet.address));
        const ledgerBalance  = await this._getLedgerBalanceForWallet(String(wallet._id));

        onChainTotal += onChainBalance;
        ledgerTotal  += ledgerBalance;

        const diff = Math.abs(onChainBalance - ledgerBalance);

        if (diff > MISMATCH_THRESHOLD) {
          anyMismatch = true;

          const severity = diff >= 100 ? 'critical' : diff >= 1 ? 'major' : 'minor';

          mismatches.push({
            walletAddress: wallet.address,
            walletId:      wallet._id,
            onChainBalance,
            ledgerBalance,
            difference:    onChainBalance - ledgerBalance,
            severity,
          });

          this.logger.error('Reconciler: BALANCE MISMATCH DETECTED', {
            walletId: String(wallet._id),
            address:  wallet.address,
            onChainBalance,
            ledgerBalance,
            diff,
            severity,
          });

          // Auto-pause withdrawals (24h TTL — admin must review and resume)
          await this.redis.set(PAUSE_WITHDRAWALS_KEY, '1',                    'EX', 24 * 60 * 60);
          await this.redis.set(PAUSE_REASON_KEY,       RECONCILER_PAUSE_REASON, 'EX', 24 * 60 * 60);
          pausedWithdrawals = true;

          await this._alert('reconciliation_mismatch', {
            reportId:      report.reportId,
            walletId:      String(wallet._id),
            address:       wallet.address,
            onChainBalance,
            ledgerBalance,
            diff,
            severity,
            message: `CRITICAL: Ledger mismatch of ${diff.toFixed(6)} USDT on wallet ${wallet.address} (${severity}). Withdrawals auto-paused for 24h.`,
          });
          alertSent = true;

        } else {
          this.logger.info('Reconciler: wallet OK', {
            address: wallet.address, onChainBalance, ledgerBalance, diff,
          });
        }
      } catch (err) {
        this.logger.error('Reconciler: failed to check wallet', {
          address: wallet.address, error: err.message,
        });
        // Don't fail the entire run for one wallet — continue and report in mismatches
        mismatches.push({
          walletAddress: wallet.address,
          walletId:      wallet._id,
          onChainBalance: 0,
          ledgerBalance:  0,
          difference:     0,
          severity:       'minor',
        });
      }
    }

    // ── Merchant Balance Drift Check ─────────────────────────────────────────
    const driftAnyMismatch = await this._checkMerchantBalanceDrift(report, mismatches);
    if (driftAnyMismatch) {
      anyMismatch = true;
      pausedWithdrawals = true;
      alertSent = true;
    }

    // ── Lift reconciler-set pause only if ALL wallets clean ──────────────────
    if (!anyMismatch && wallets.length > 0) {
      const pauseReason = await this.redis.get(PAUSE_REASON_KEY);
      if (pauseReason === RECONCILER_PAUSE_REASON) {
        await this.redis.del(PAUSE_WITHDRAWALS_KEY);
        await this.redis.del(PAUSE_REASON_KEY);
        this.logger.info('Reconciler: all wallets balanced — withdrawal pause lifted');
      } else if (pauseReason) {
        this.logger.info('Reconciler: all wallets balanced — pause kept (set by admin, not by reconciler)');
      }
    }

    return {
      passed:           !anyMismatch,
      walletsChecked:   wallets.length,
      mismatches,
      onChainTotal:     parseFloat(onChainTotal.toFixed(6)),
      ledgerTotal:      parseFloat(ledgerTotal.toFixed(6)),
      totalDiff:        parseFloat(Math.abs(onChainTotal - ledgerTotal).toFixed(6)),
      pausedWithdrawals,
      alertSent,
    };
  }

  /**
   * Compute ledger balance per wallet using invoices linked to that wallet.
   * Compares on-chain balance against ALL receivable credits minus debits
   * for that specific wallet's invoices.
   */
  async _getLedgerBalanceForWallet(walletId) {
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

  /**
   * Compares the MerchantBalance cache against the authoritative LedgerEntry aggregate.
   */
  async _checkMerchantBalanceDrift(report, mismatches) {
    this.logger.info('Reconciler: checking merchant balance drift', { reportId: report.reportId });
    let anyMismatch = false;

    try {
      // 1. Group ledger entries by merchantId
      const ledgerAgg = await LedgerEntry.aggregate([
        { $match: { account: 'merchant_receivable' } },
        { 
          $group: { 
            _id: '$merchantId', 
            credits: { $sum: { $cond: [{ $eq: ['$type', 'credit'] }, '$amount', 0] } }, 
            debits:  { $sum: { $cond: [{ $eq: ['$type', 'debit'] }, '$amount', 0] } } 
          } 
        }
      ]);
      const ledgerBalances = new Map(ledgerAgg.map(acc => [String(acc._id), acc.credits - acc.debits]));

      // 2. Fetch all MerchantBalance records
      const merchantBalances = await MerchantBalance.find().select('merchantId availableBalance').lean();

      for (const mb of merchantBalances) {
        const merchantIdStr = String(mb.merchantId);
        const ledgerBal = ledgerBalances.get(merchantIdStr) || 0;
        const cachedBal = mb.availableBalance || 0;
        const diff = Math.abs(cachedBal - ledgerBal);

        if (diff > MISMATCH_THRESHOLD) {
          anyMismatch = true;
          const severity = diff >= 100 ? 'critical' : diff >= 1 ? 'major' : 'minor';

          mismatches.push({
            merchantId: merchantIdStr,
            merchantBalance: cachedBal,
            ledgerBalance: ledgerBal,
            difference: cachedBal - ledgerBal,
            severity,
            type: 'merchant_balance_drift'
          });

          this.logger.error('Reconciler: MERCHANT BALANCE DRIFT DETECTED', {
            merchantId: merchantIdStr,
            merchantBalance: cachedBal,
            ledgerBalance: ledgerBal,
            diff,
            severity,
          });

          // Auto-pause withdrawals
          await this.redis.set(PAUSE_WITHDRAWALS_KEY, '1',                    'EX', 24 * 60 * 60);
          await this.redis.set(PAUSE_REASON_KEY,       RECONCILER_PAUSE_REASON, 'EX', 24 * 60 * 60);

          await this._alert('merchant_balance_drift', {
            reportId: report.reportId,
            merchantId: merchantIdStr,
            merchantBalance: cachedBal,
            ledgerBalance: ledgerBal,
            diff,
            severity,
            message: `CRITICAL: MerchantBalance drift of ${diff.toFixed(6)} USDT for merchant ${merchantIdStr} (${severity}). Withdrawals auto-paused for 24h.`,
          });
        }
      }
    } catch (err) {
      this.logger.error('Reconciler: failed to check merchant balance drift', { error: err.message });
    }

    return anyMismatch;
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
