'use strict';

/**
 * @module withdrawal-engine/refundProcessor
 *
 * Refund Processor — Handles the execution of approved refunds.
 *
 * FLOW:
 *   1. Consumes `xcg:refund:process` (refunds that are newly 'approved').
 *   2. Selects an active hot wallet with sufficient balance.
 *   3. Starts a Mongo session:
 *        - Debits merchant_receivable (Ledger).
 *        - Credits refund_outgoing (Ledger).
 *        - Decrements cached MerchantBalance.
 *        - Updates Refund status to 'signing'.
 *   4. Publishes to `xcg:signing:request` for broadcasting.
 */

const mongoose = require('mongoose');
const { Refund, LedgerEntry, MerchantBalance, Wallet } = require('@xcg/database');
const cache = require('@xcg/cache');
const { v4: uuidv4 } = require('uuid');

class RefundProcessor {
  /**
   * @param {object} opts
   * @param {object} opts.redis
   * @param {object} opts.signingPublisher - publisher for SIGNING_REQUEST
   * @param {object} opts.alertPublisher   - publisher for SYSTEM_ALERT
   * @param {object} opts.logger
   */
  constructor({ redis, signingPublisher, alertPublisher, logger }) {
    this.redis            = redis;
    this.signingPublisher = signingPublisher;
    this.alertPublisher   = alertPublisher;
    this.logger           = logger;
  }

  async handle(data, idempotencyKey) {
    const { refundId } = data;
    this.logger.info('RefundProcessor: picking up refund', { refundId });

    const refund = await Refund.findOne({ refundId, status: 'approved' });
    if (!refund) {
      this.logger.warn('RefundProcessor: refund not found or not approved', { refundId });
      return;
    }

    // ── 1. Select source wallet ──────────────────────────────────────────────
    const activeWallets = await cache.getActiveWallets(
      this.redis,
      async () => Wallet
        .find({ isActive: true, type: { $in: ['hot', 'receiving'] } })
        .select('_id address balance')
        .lean(),
    );

    // Pick wallet with highest USDT balance
    const wallet = (activeWallets || [])
      .filter((w) => w._id && w.address)
      .sort((a, b) => {
        const balA = parseFloat(a.balance?.usdt || 0);
        const balB = parseFloat(b.balance?.usdt || 0);
        return balB - balA;
      })[0] || null;

    if (!wallet) {
      this.logger.error('RefundProcessor: no available hot wallet for refund', { refundId });
      if (this.alertPublisher) {
        await this.alertPublisher.publish({
          type: 'no_hot_wallet',
          service: 'refundProcessor',
          message: `Cannot process refund ${refundId} — no hot wallet available.`,
        }, `alert:no_hot_wallet:${refundId}`);
      }
      return;
    }

    const amountFloat = refund.refundAmount;

    // ── 2. DB Transaction (Ledger & State) ───────────────────────────────────
    const session = await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        // Debit merchant_receivable (funds are leaving platform)
        // Credit refund_outgoing (liability that signing service will clear upon confirmation)
        const debitId  = `led_${uuidv4().replace(/-/g, '')}`;
        const creditId = `led_${uuidv4().replace(/-/g, '')}`;

        await LedgerEntry.create([
          {
            entryId:            debitId,
            account:            'merchant_receivable',
            type:               'debit',
            amount:             amountFloat,
            currency:           'USDT',
            merchantId:         refund.merchantId,
            invoiceId:          refund.invoiceId,
            counterpartEntryId: creditId,
            description:        `Refund debit — ref ${refund.refundId}`,
            idempotencyKey:     `ledger:ref-debit:${idempotencyKey}`,
          },
          {
            entryId:            creditId,
            account:            'refund_outgoing',
            type:               'credit',
            amount:             amountFloat,
            currency:           'USDT',
            merchantId:         refund.merchantId,
            invoiceId:          refund.invoiceId,
            counterpartEntryId: debitId,
            description:        `Refund credit — ref ${refund.refundId}`,
            idempotencyKey:     `ledger:ref-credit:${idempotencyKey}`,
          },
        ], { session });

        // Update Cached Balance
        await MerchantBalance.incrementBalance(refund.merchantId, {
          availableBalance: -amountFloat,
          totalRefunded:     amountFloat,
          refundCount:       1,
        }, session);

        // Update Refund Status
        await Refund.findByIdAndUpdate(refund._id, {
          $set: {
            fromWalletId: wallet._id,
            status: 'signing'
          }
        }, { session });
      });

      this.logger.info('RefundProcessor: DB transaction complete, pushing to signing', { refundId });
    } catch (err) {
      this.logger.error('RefundProcessor: DB transaction failed', { refundId, error: err.message });
      throw err;
    } finally {
      await session.endSession();
    }

    // ── 3. Publish to Signing Service ─────────────────────────────────────────
    if (this.signingPublisher) {
      await this.signingPublisher.publish({
        type:         'refund',
        sourceId:     String(refund._id),  // To link it back after signing
        amount:       String(amountFloat),
        toAddress:    refund.toAddress,
        fromAddress:  wallet.address,
        currency:     'USDT',
        network:      'tron',
      }, `sign:ref:${idempotencyKey}`);
    }
  }
}

module.exports = RefundProcessor;
