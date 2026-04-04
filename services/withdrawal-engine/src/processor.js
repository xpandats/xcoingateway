'use strict';

/**
 * @module withdrawal-engine/processor
 *
 * Withdrawal Processor — Validates and queues signing requests.
 *
 * SECURITY RULES (NON-NEGOTIABLE):
 *   1. Ledger balance must be confirmed BEFORE withdrawal
 *   2. 1-hour cooling-off period after last deposit
 *   3. Per-transaction limit enforced (1000 USDT default)
 *   4. Daily cap enforced (10,000 USDT default per merchant)
 *   5. Destination address must not be our own wallet
 *   6. High-value (>5000 USDT) requires admin approval flag
 *   7. Idempotency key prevents duplicate processing
 *   8. Signing request is HMAC-signed before sending to Zone 3
 */

const { v4: uuidv4 }  = require('uuid');
const mongoose         = require('mongoose');
const { Withdrawal, LedgerEntry, Wallet, Merchant, Dispute } = require('@xcg/database');
const { DISPUTE_STATUS } = require('@xcg/common').constants;

class WithdrawalProcessor {
  /**
   * @param {object} opts
   * @param {object} opts.signingPublisher  - Publisher for SIGNING_REQUEST queue
   * @param {object} opts.alertPublisher    - Publisher for SYSTEM_ALERT queue
   * @param {object} opts.config            - config.wallet
   * @param {string} opts.tronNetwork       - 'mainnet' | 'testnet'
   * @param {object} opts.logger
   */
  constructor({ signingPublisher, alertPublisher, tronAdapter, config, tronNetwork, logger }) {
    this.signingPublisher = signingPublisher;
    this.alertPublisher   = alertPublisher;
    this.tronAdapter      = tronAdapter;   // For energy checks
    this.config           = config;
    this.tronNetwork      = tronNetwork;
    this.logger           = logger;
  }

  /**
   * Process a withdrawal eligible event from the Matching Engine.
   * @param {object} data           - { merchantId, invoiceId, amount }
   * @param {string} idempotencyKey - Queue idempotency key
   * @param {object} [publisherSelf] - Self-publisher for re-queuing on cooling-off
   */
  async handle(data, idempotencyKey, publisherSelf = null) {
    const { merchantId, invoiceId, amount } = data;
    const amountFloat = parseFloat(amount);

    this.logger.info('WithdrawalProcessor: processing withdrawal eligible', {
      merchantId, invoiceId, amount,
    });

    // ── 1. Load merchant withdrawal address ───────────────────────────────────
    const merchant = await Merchant.findById(merchantId)
      .select('withdrawalAddress businessName isActive dailyWithdrawalUsed dailyCapResetAt')
      .lean();

    if (!merchant || !merchant.isActive) {
      this.logger.warn('WithdrawalProcessor: merchant not found or inactive', { merchantId });
      return;
    }
    if (!merchant.withdrawalAddress) {
      this.logger.warn('WithdrawalProcessor: merchant has no withdrawal address set', { merchantId });
      return; // Funds held until merchant sets address
    }

    // ── 2. Validate toAddress is not one of our own wallets ───────────────────
    const isOwnWallet = await Wallet.exists({ address: merchant.withdrawalAddress, isActive: true });
    if (isOwnWallet) {
      this.logger.error('WithdrawalProcessor: withdrawal to own wallet rejected', {
        merchantId,
        toAddress: merchant.withdrawalAddress,
      });
      await this._alert('withdrawal_to_own_wallet', { merchantId, toAddress: merchant.withdrawalAddress });
      return;
    }

    // ── 2b. SECURITY: Check for active disputes against this merchant ─────────
    // Disputed funds MUST NOT be withdrawn until the dispute is resolved.
    // Without this check, a merchant could withdraw funds while a dispute is pending,
    // leaving the platform unable to issue a refund.
    const activeDispute = await Dispute.exists({
      merchantId,
      status: { $in: [DISPUTE_STATUS.OPENED, DISPUTE_STATUS.MERCHANT_RESPONDED, DISPUTE_STATUS.UNDER_REVIEW] },
    });
    if (activeDispute) {
      this.logger.warn('WithdrawalProcessor: BLOCKED — active dispute exists for merchant', {
        merchantId,
        message: 'Cannot withdraw while a dispute is open',
      });
      await this._alert('withdrawal_blocked_active_dispute', {
        merchantId,
        message: `Withdrawal blocked: merchant ${merchantId} has an active dispute. Funds held until resolved.`,
      });
      return;
    }


    // ── 3. Per-transaction limit check ────────────────────────────────────────
    const perTxLimit = this.config.perTxWithdrawalLimit; // 1000 USDT
    if (amountFloat > perTxLimit) {
      this.logger.warn('WithdrawalProcessor: amount exceeds per-tx limit', { amount, perTxLimit });
      // Split into smaller chunks is out of scope for MVP — hold for manual review
      await this._alert('withdrawal_over_per_tx_limit', {
        merchantId, amount, perTxLimit,
        message: 'Withdrawal amount exceeds per-tx limit — needs manual review',
      });
      return;
    }

    // ── 4. Ledger balance check ───────────────────────────────────────────────
    const balance = await this._getMerchantBalance(merchantId);
    if (balance < amountFloat) {
      this.logger.error('WithdrawalProcessor: insufficient ledger balance', {
        merchantId, requested: amountFloat, balance,
      });
      return; // Reconciliation will catch mismatches
    }

    // ── 5. Daily cap check ───────────────────────────────────────────────────
    const dailyCap = this.config.dailyWithdrawalCap; // 10000 USDT
    const dailyUsed = await this._getDailyWithdrawalTotal(merchantId);
    if (dailyUsed + amountFloat > dailyCap) {
      this.logger.warn('WithdrawalProcessor: daily cap reached', {
        merchantId, dailyUsed, amountFloat, dailyCap,
      });
      await this._alert('daily_cap_reached', { merchantId, dailyUsed, dailyCap });
      return;
    }

    // ── 6. High-value flag ───────────────────────────────────────────────────
    const requiresApproval = amountFloat > this.config.highValueThreshold;

    // ── 7. Cooling-off check — RE-QUEUE with delay instead of silent drop ──────
    const cooldownMs = this.config.withdrawalCooldownMs; // 1 hour
    const lastDeposit = await this._getLastDepositTime(merchantId);
    if (lastDeposit && (Date.now() - lastDeposit.getTime()) < cooldownMs) {
      const remainingMs = cooldownMs - (Date.now() - lastDeposit.getTime());
      const remainingMin = Math.ceil(remainingMs / 60000);
      this.logger.info('WithdrawalProcessor: cooling-off period active — re-queuing with delay', {
        merchantId, remainingMinutes: remainingMin,
      });

      // Re-queue with BullMQ delay — will be retried after cooling-off expires
      if (publisherSelf) {
        await publisherSelf.publish(
          data,
          `${idempotencyKey}:retry:${Date.now()}`,
          { delay: remainingMs + 5000 }, // 5s buffer after cooldown
        );
      } else {
        this.logger.warn('WithdrawalProcessor: no self-publisher — cooling-off deferred but not re-queued', { merchantId });
      }
      return;
    }

    // ── 8. Select source wallet ──────────────────────────────────────────────
    const wallet = await Wallet.findOne({ isActive: true, type: { $in: ['hot', 'receiving'] } })
      .sort({ 'balance.usdt': -1 })
      .select('_id address')
      .lean();

    if (!wallet) {
      this.logger.error('WithdrawalProcessor: no available hot wallet');
      await this._alert('no_hot_wallet', { merchantId, amount });
      return;
    }

    // ── 9. Create Withdrawal record ──────────────────────────────────────────
    const session = await mongoose.startSession();
    let withdrawal;

    try {
      await session.withTransaction(async () => {
        withdrawal = await Withdrawal.create([{
          withdrawalId:    `wdl_${uuidv4().replace(/-/g, '')}`,
          merchantId,
          amount:          amountFloat,
          netAmount:       amountFloat, // No withdrawal fee for MVP
          currency:        'USDT',
          network:         'tron',
          toAddress:       merchant.withdrawalAddress,
          fromWalletId:    wallet._id,
          status:          requiresApproval ? 'pending_approval' : 'processing',
          requiresApproval,
          idempotencyKey,
        }], { session });
        withdrawal = withdrawal[0];

        // Debit ledger for this withdrawal (reserve the funds)
        const debitId = `led_${uuidv4().replace(/-/g, '')}`;
        const creditId = `led_${uuidv4().replace(/-/g, '')}`;

        await LedgerEntry.create([
          {
            entryId:          debitId,
            account:          'merchant_receivable',
            type:             'debit',
            amount:           amountFloat,
            currency:         'USDT',
            merchantId,
            withdrawalId:     withdrawal._id,
            counterpartEntryId: creditId,
            description:      `Withdrawal debit — wdl ${withdrawal.withdrawalId}`,
            idempotencyKey:   `ledger:wdl-debit:${idempotencyKey}`,
          },
          {
            entryId:          creditId,
            account:          'merchant_withdrawal',
            type:             'credit',
            amount:           amountFloat,
            currency:         'USDT',
            merchantId,
            withdrawalId:     withdrawal._id,
            counterpartEntryId: debitId,
            description:      `Withdrawal credit — wdl ${withdrawal.withdrawalId}`,
            idempotencyKey:   `ledger:wdl-credit:${idempotencyKey}`,
          },
        ], { session });
      });

      this.logger.info('WithdrawalProcessor: withdrawal record created', {
        withdrawalId: withdrawal.withdrawalId,
        merchantId, amount: amountFloat,
        requiresApproval,
      });

    } catch (err) {
      this.logger.error('WithdrawalProcessor: DB transaction failed', { error: err.message });
      throw err;
    } finally {
      await session.endSession();
    }

    // ── 10. Skip signing if requires admin approval ───────────────────────────
    if (requiresApproval) {
      await this._alert('withdrawal_requires_approval', {
        withdrawalId: withdrawal.withdrawalId,
        merchantId, amount: amountFloat,
        message: `Withdrawal of ${amountFloat} USDT requires admin approval`,
      });
      return;
    }

    // ── 11. Energy check BEFORE submitting to signing service ─────────────────
    // Per spec: if insufficient energy → queue withdrawal, alert admin
    if (this.tronAdapter) {
      const hasSufficientEnergy = await this.tronAdapter.hasSufficientEnergy(wallet.address);
      if (!hasSufficientEnergy) {
        this.logger.warn('WithdrawalProcessor: insufficient Tron energy — deferring withdrawal', {
          walletAddress: wallet.address,
          withdrawalId:  withdrawal.withdrawalId,
        });
        await this._alert('insufficient_energy', {
          withdrawalId:  withdrawal.withdrawalId,
          walletAddress: wallet.address,
          merchantId,    amount: amountFloat,
          message: `Withdrawal deferred: wallet ${wallet.address} has insufficient Tron energy. Please stake TRX or use energy rental.`,
        });
        // Update withdrawal status to 'queued' — admin must resolve energy then re-trigger
        await Withdrawal.findByIdAndUpdate(withdrawal._id, { $set: { status: 'queued', reviewNotes: 'Deferred: insufficient Tron energy' } });
        return;
      }
    }

    // ── 12. Submit to Signing Service via queue ──────────────────────────────
    const requestId = uuidv4();
    await this.signingPublisher.publish(
      {
        requestId,
        withdrawalId: String(withdrawal._id),
        walletId:     String(wallet._id),
        toAddress:    merchant.withdrawalAddress,
        amount:       amountFloat.toFixed(6),
        network:      this.tronNetwork,
      },
      `signing:${String(withdrawal._id)}`,
    );

    this.logger.info('WithdrawalProcessor: signing request submitted', {
      requestId,
      withdrawalId: withdrawal.withdrawalId,
    });
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────────

  async _getMerchantBalance(merchantId) {
    const result = await LedgerEntry.aggregate([
      { $match: { merchantId: new (require('mongoose').Types.ObjectId)(merchantId), account: 'merchant_receivable' } },
      { $group: { _id: null, credits: { $sum: { $cond: [{ $eq: ['$type', 'credit'] }, '$amount', 0] } }, debits: { $sum: { $cond: [{ $eq: ['$type', 'debit'] }, '$amount', 0] } } } },
    ]);
    if (!result.length) return 0;
    return result[0].credits - result[0].debits;
  }

  async _getDailyWithdrawalTotal(merchantId) {
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    const result = await Withdrawal.aggregate([
      {
        $match: {
          merchantId: new (require('mongoose').Types.ObjectId)(merchantId),
          status: { $in: ['processing', 'completed', 'confirmed'] },
          createdAt: { $gte: startOfDay },
        },
      },
      { $group: { _id: null, total: { $sum: '$amount' } } },
    ]);
    return result.length ? result[0].total : 0;
  }

  async _getLastDepositTime(merchantId) {
    const { LedgerEntry: LE } = require('@xcg/database');
    const last = await LE.findOne({
      merchantId: new (require('mongoose').Types.ObjectId)(merchantId),
      account: 'merchant_receivable',
      type: 'credit',
    }).sort({ createdAt: -1 }).select('createdAt').lean();
    return last ? last.createdAt : null;
  }

  async _alert(type, payload) {
    try {
      await this.alertPublisher.publish(
        { type, service: 'withdrawal-engine', ...payload },
        `alert:${type}:${Date.now()}`,
      );
    } catch (err) {
      this.logger.error('WithdrawalProcessor: alert failed', { type, error: err.message });
    }
  }
}

module.exports = WithdrawalProcessor;
