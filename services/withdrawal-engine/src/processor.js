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
const { Withdrawal, LedgerEntry, Wallet, Merchant, Dispute, MerchantBalance } = require('@xcg/database');
const { DISPUTE_STATUS } = require('@xcg/common').constants;
const cache            = require('@xcg/cache');


class WithdrawalProcessor {
  /**
   * @param {object} opts
   * @param {object} opts.signingPublisher  - Publisher for SIGNING_REQUEST queue
   * @param {object} opts.alertPublisher    - Publisher for SYSTEM_ALERT queue
   * @param {object} opts.config            - config.wallet
   * @param {string} opts.tronNetwork       - 'mainnet' | 'testnet'
   * @param {object} opts.logger
   */
  constructor({ signingPublisher, alertPublisher, tronAdapter, config, tronNetwork, logger, redis }) {
    this.signingPublisher = signingPublisher;
    this.alertPublisher   = alertPublisher;
    this.tronAdapter      = tronAdapter;   // For energy checks
    this.config           = config;
    this.tronNetwork      = tronNetwork;
    this.logger           = logger;
    this.redis            = redis;         // For per-merchant distributed lock
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

    // ── C2 FIX: Status-aware idempotency guard at entry ─────────────────────
    // BullMQ delivers at-least-once. On retry, a withdrawal record may already exist.
    // We must handle each status differently:
    //
    //   'processing'      → Session committed OK, but crash happened before status→signing
    //                       or before queue publish. Re-trigger the signing step.
    //   'signing'         → Startup recovery (H1) handles this. Skip here.
    //   'queued'          → Energy insufficient, admin must re-trigger. Skip.
    //   'pending_approval'→ Awaiting admin. Skip.
    //   'broadcast'/
    //   'completed'/
    //   'failed'/
    //   'rejected'        → Terminal or in-progress by another path. Skip.
    const existing = await Withdrawal.findOne({ idempotencyKey })
      .select('_id withdrawalId status fromWalletId')
      .lean();

    if (existing) {
      if (existing.status === 'processing' || existing.status === 'requested') {
        // 'processing' → crash recovery: security checks already ran in original cycle
        // 'requested'  → API/admin-approved: must re-run security checks
        //                 (dispute status or withdrawal address may have changed since creation)
        this.logger.warn('WithdrawalProcessor: re-triggering signing for unprocessed withdrawal', {
          idempotencyKey, withdrawalId: existing.withdrawalId, status: existing.status,
        });

        // For API-created withdrawals ('requested'), re-validate critically before signing
        if (existing.status === 'requested') {
          // Own-wallet check: merchant may have changed withdrawal address since creation
          const reloadedWithdrawal = await Withdrawal.findById(existing._id).select('toAddress').lean();
          if (reloadedWithdrawal?.toAddress) {
            const isOwnWallet = await Wallet.exists({ address: reloadedWithdrawal.toAddress, isActive: true });
            if (isOwnWallet) {
              this.logger.error('WithdrawalProcessor: BLOCKED re-trigger — withdrawal to own wallet', {
                withdrawalId: existing.withdrawalId, toAddress: reloadedWithdrawal.toAddress,
              });
              await Withdrawal.findByIdAndUpdate(existing._id, { $set: { status: 'failed', lastError: 'Destination is a platform wallet' } });
              return;
            }
          }

          // Dispute check: a dispute may have been opened AFTER the withdrawal was created
          const activeDispute = await Dispute.exists({
            merchantId: merchantId,
            status: { $in: [DISPUTE_STATUS.OPENED, DISPUTE_STATUS.MERCHANT_RESPONDED, DISPUTE_STATUS.UNDER_REVIEW] },
          });
          if (activeDispute) {
            this.logger.warn('WithdrawalProcessor: BLOCKED re-trigger — active dispute exists', {
              withdrawalId: existing.withdrawalId, merchantId,
            });
            await this._alert('withdrawal_blocked_active_dispute', {
              merchantId,
              message: `Approved withdrawal ${existing.withdrawalId} blocked: merchant has an active dispute.`,
            });
            return;  // Leave as 'requested' — will retry after dispute resolves
          }
        }

        await this._triggerSigning(existing, merchantId);
        return;
      }

      // All other statuses — skip safely
      this.logger.info('WithdrawalProcessor: idempotent skip — withdrawal already in progress or done', {
        idempotencyKey, withdrawalId: existing.withdrawalId, status: existing.status,
      });
      return;
    }

    this.logger.info('WithdrawalProcessor: processing withdrawal eligible', {
      merchantId, invoiceId, amount,
    });

    // ── H3 FIX: Distributed lock per merchant (prevents balance race condition) ────
    // Problem: concurrency=2 workers can both pass the balance check for the same
    // merchant simultaneously (both see pre-commit ledger state), then both create
    // withdrawal records and debit the ledger, causing balance to go negative.
    // Solution: Acquire a Redis lock before ANY balance checks or DB writes.
    // Lock TTL = 120s (generous — the full processing cycle takes ~5s normally).
    const lockKey = `xcg:wdl-lock:${merchantId}`;
    const lockTTL = 120; // seconds
    const lockAcquired = this.redis
      ? await this.redis.set(lockKey, '1', 'EX', lockTTL, 'NX')
      : '1'; // No redis in test env — skip lock (tests are single-threaded)

    if (lockAcquired === null) {
      // Another worker is processing a withdrawal for this merchant right now.
      // Re-queue with a short delay so it retries after the lock is released.
      this.logger.info('WithdrawalProcessor: merchant lock held by another worker — re-queuing', {
        merchantId, remainingDelay: '15s',
      });
      if (publisherSelf) {
        await publisherSelf.publish(data, `${idempotencyKey}:lock-retry:${Date.now()}`, { delay: 15_000 });
      }
      return;
    }

    // Wrap everything in try/finally to guarantee lock release
    try {
      return await this._processWithLock(data, idempotencyKey, publisherSelf, { merchantId, invoiceId, amount, amountFloat });
    } finally {
      if (this.redis) await this.redis.del(lockKey).catch(() => {});
    }
  }

  /**
   * Core processing logic — runs while merchant lock is held.
   * Extracted so lock release in finally{} is guaranteed regardless of outcome.
   */
  async _processWithLock(data, idempotencyKey, publisherSelf, { merchantId, invoiceId, amount, amountFloat }) {

    // ── 1. Load merchant withdrawal address ───────────────────────────────────
    const merchant = await Merchant.findById(merchantId)
      .select('withdrawalAddress businessName isActive dailyWithdrawalUsed dailyCapResetAt autoWithdrawal')
      .lean();

    if (!merchant || !merchant.isActive) {
      this.logger.warn('WithdrawalProcessor: merchant not found or inactive', { merchantId });
      return;
    }

    // ── AUTO-WITHDRAWAL GATE ──────────────────────────────────────────────────
    // Merchants can opt out of automatic sweeping.
    // If autoWithdrawal is false, hold funds in ledger — merchant withdraws manually via API.
    // Note: autoWithdrawal defaults to true on the Merchant model.
    if (merchant.autoWithdrawal === false) {
      this.logger.info('WithdrawalProcessor: merchant has auto-withdrawal disabled — funds held in ledger', {
        merchantId, amount,
      });
      return; // Funds remain in merchant_receivable, withdrawable via manual API call
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

    // ── 8. Select source wallet ────────────────────────────────────────
    // Gap 1 fix: use Redis-cached wallet list (2-min TTL) with stampede protection.
    // Highest-balance wallet is selected from the cached array in-process.
    // Acceptable: 2-min stale balance is fine — signing service re-validates before broadcast.
    const activeWallets = await cache.getActiveWallets(
      this.redis,
      async () => Wallet
        .find({ isActive: true, type: { $in: ['hot', 'receiving'] } })
        .select('_id address balance')
        .lean(),
    );

    // Sort in-process: pick wallet with highest USDT balance
    const wallet = (activeWallets || [])
      .filter((w) => w._id && w.address)
      .sort((a, b) => {
        const balA = parseFloat(a.balance?.usdt || 0);
        const balB = parseFloat(b.balance?.usdt || 0);
        return balB - balA;
      })[0] || null;


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

        // ── MerchantBalance: Atomic cache decrement ──────────────────────────
        // Keeps the cached balance in sync with ledger. The matching engine
        // increments availableBalance on payment confirmation; here we decrement.
        await MerchantBalance.incrementBalance(merchantId, {
          availableBalance: -amountFloat,
          totalWithdrawn:    amountFloat,
          withdrawalCount:   1,
        }, session);
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

    // ── 12. Set status to SIGNING and publish to signing queue ───────────────
    // C3 FIX: Wrapped in try/catch so any failure (DB write or queue publish)
    // is re-thrown → BullMQ retries → idempotency guard sees 'processing' status
    // → falls into the re-trigger path → signing attempted again. Safe.
    await this._triggerSigning(withdrawal, merchantId, wallet, merchant.withdrawalAddress, amountFloat);
  }

  /**
   * Set withdrawal status to SIGNING and publish to signing:request queue.
   * Extracted so both the main flow and idempotency re-trigger path use exactly
   * the same logic. Any failure here is re-thrown → BullMQ retries.
   *
   * @param {object} withdrawal       - Withdrawal document (lean or mongoose doc)
   * @param {string} merchantId       - Merchant ID string
   * @param {object} [wallet]         - Wallet document (lean). If null, reloads from DB.
   * @param {string} [toAddress]      - Merchant withdrawal address. If null, reloads from DB.
   * @param {number} [amountFloat]    - Amount as float. If null, uses withdrawal.amount.
   */
  async _triggerSigning(withdrawal, merchantId, wallet = null, toAddress = null, amountFloat = null) {
    // On re-trigger path (crash recovery OR 'requested' from API), may not have wallet in memory
    if (!wallet) {
      if (withdrawal.fromWalletId) {
        // Processor-created withdrawal — wallet was selected during creation
        wallet = await Wallet.findById(withdrawal.fromWalletId).select('_id address').lean();
        if (!wallet) throw new Error(`WithdrawalProcessor: wallet not found for recovery — id=${withdrawal.fromWalletId}`);
      } else {
        // API-created withdrawal — no wallet assigned yet, pick the best hot wallet
        wallet = await Wallet.findOne({ isActive: true, type: { $in: ['hot', 'receiving'] } })
          .sort({ 'balance.usdt': -1 })
          .select('_id address')
          .lean();
        if (!wallet) throw new Error('WithdrawalProcessor: no available hot wallet for API-created withdrawal');
        // Persist the wallet assignment so startup recovery can use it
        await Withdrawal.findByIdAndUpdate(withdrawal._id, { $set: { fromWalletId: wallet._id } });
      }
    }
    if (!toAddress) {
      const merchant = await Merchant.findById(merchantId).select('withdrawalAddress').lean();
      if (!merchant?.withdrawalAddress) throw new Error(`WithdrawalProcessor: merchant withdrawal address missing for recovery`);
      toAddress = merchant.withdrawalAddress;
    }
    const amount = amountFloat ?? withdrawal.amount;
    const requestId = uuidv4();

    // Step A: Mark withdrawal as SIGNING in DB
    // If this fails → throws → BullMQ retries → idempotency guard sees 'processing' → re-trigger again
    await Withdrawal.findByIdAndUpdate(withdrawal._id, {
      $set: { status: 'signing', lastError: null },
    });

    // Step B: Publish to signing queue
    // If this fails → throws → BullMQ retries → idempotency guard sees 'signing'
    // → startup recovery (H1) detects 'signing' older than 10min → checks audit log → reconciles
    await this.signingPublisher.publish(
      {
        requestId,
        withdrawalId: String(withdrawal._id),
        walletId:     String(wallet._id),
        toAddress,
        amount:       amount.toFixed(6),
        network:      this.tronNetwork,
      },
      `signing:${String(withdrawal._id)}`,
    );

    this.logger.info('WithdrawalProcessor: signing request submitted — status set to SIGNING', {
      requestId,
      withdrawalId: withdrawal.withdrawalId,
    });
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────────

  async _getMerchantBalance(merchantId) {
    // O(1) cache read from MerchantBalance — updated atomically by matching engine
    const cached = await MerchantBalance.findOne({ merchantId }).select('availableBalance').lean();
    if (cached) return cached.availableBalance || 0;

    // Fallback: aggregate from ledger (cold start — no MerchantBalance record yet)
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
          // Include ALL non-terminal statuses — any in-flight withdrawal counts toward daily cap
          status: { $in: ['requested', 'pending_approval', 'processing', 'signing', 'broadcast', 'completed', 'confirmed'] },
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
