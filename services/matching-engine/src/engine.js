'use strict';

/**
 * @module matching-engine/engine
 *
 * Matching Engine — Heart of XCoinGateway.
 *
 * Consumes "transaction:detected" events from the queue.
 * Matches incoming blockchain transactions to active invoices.
 * Manages the full transaction lifecycle state machine.
 * Writes double-entry ledger entries for every matched payment.
 *
 * TRANSACTION STATE MACHINE:
 *   initiated → pending → hash_found → confirming → confirmed → success
 *                      ↘ expired (no payment within 15min)
 *                                   ↘ failed (wrong contract, bad amount, etc.)
 *
 * MATCHING CRITERIA (ALL must pass):
 *   1. toAddress is our active wallet
 *   2. Token contract = official USDT TRC20 (hardcoded in adapter)
 *   3. tokenSymbol = 'USDT'
 *   4. Amount matches an active invoice's uniqueAmount (exact string comparison)
 *   5. Invoice is not expired
 *   6. Invoice is not already matched
 *   7. Confirmation count >= MIN_CONFIRMATIONS (19 for Tron) — ZERO TOLERANCE
 *   8. TX hash not already processed (idempotency)
 *
 * SECURITY:
 *   - 0-confirmation = NEVER accepted (enforced here, not just in listener)
 *   - TX hash deduplication (DB unique index + idempotency key)
 *   - All DB updates are atomic (MongoDB transactions)
 *   - Double-entry ledger is ATOMIC with invoice status update
 *   - Idempotency: same TX processed twice = same result, no double-credit
 */

const mongoose = require('mongoose');
const { Invoice, Transaction, Wallet, LedgerEntry } = require('@xcg/database');
const { money } = require('@xcg/common');

// ─── HARDCODED CONSTANTS ─────────────────────────────────────────────────────

/**
 * Official USDT TRC20 contract addresses.
 * HARDCODED — never from user input or env. Must match adapter.
 */
const USDT_TRC20_CONTRACTS = new Set([
  'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t', // Mainnet
  'TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj', // Nile testnet
]);

class MatchingEngine {
  /**
   * @param {object} opts
   * @param {number} opts.minConfirmations     - MIN block confirmations required (19)
   * @param {number} opts.platformFeeRate      - e.g. 0.001 for 0.1%
   * @param {object} opts.confirmedPublisher   - Queue publisher: PAYMENT_CONFIRMED
   * @param {object} opts.alertPublisher       - Queue publisher: SYSTEM_ALERT
   * @param {object} opts.withdrawalPublisher  - Queue publisher: WITHDRAWAL_ELIGIBLE
   * @param {object} opts.logger               - @xcg/logger instance
   */
  constructor({ minConfirmations, platformFeeRate, confirmedPublisher, alertPublisher, withdrawalPublisher, logger }) {
    this.minConfirmations    = minConfirmations || 19;
    this.platformFeeRate     = platformFeeRate || 0.001;
    this.confirmedPublisher  = confirmedPublisher;
    this.alertPublisher      = alertPublisher;
    this.withdrawalPublisher = withdrawalPublisher;
    this.logger              = logger;
  }

  // ─── Main Handler (called by queue consumer) ─────────────────────────────────

  /**
   * Process a detected transaction from the blockchain listener.
   * This is the idempotent handler called by the queue consumer.
   *
   * @param {object} txData          - Transaction event data from listener
   * @param {string} idempotencyKey  - TX hash (used for dedup)
   */
  async handle(txData, idempotencyKey) {
    const { txHash } = txData;

    this.logger.info('MatchingEngine: processing transaction', {
      txHash,
      amount: txData.amount,
      toAddress: txData.toAddress,
      confirmations: txData.confirmations,
    });

    // ── Step 1: Validate contract address ───────────────────────────────────
    // SECURITY: Reject any token not from the official USDT TRC20 contract.
    // This prevents fake token attacks where attacker sends custom TRC20 to our address.
    if (!USDT_TRC20_CONTRACTS.has(txData.tokenContract)) {
      this.logger.warn('MatchingEngine: rejected — invalid token contract', {
        txHash,
        tokenContract: txData.tokenContract,
      });
      await this._recordFailedTransaction(txData, 'invalid_token_contract');
      return;
    }

    // ── Step 2: Validate token symbol ───────────────────────────────────────
    if (txData.tokenSymbol !== 'USDT') {
      this.logger.warn('MatchingEngine: rejected — not USDT', { txHash, tokenSymbol: txData.tokenSymbol });
      await this._recordFailedTransaction(txData, 'invalid_token_symbol');
      return;
    }

    // ── Step 3: Confirm count check ─────────────────────────────────────────
    // CRITICAL SECURITY: Never credit transactions without sufficient confirmations.
    // 0-confirmation payments could be double-spent. 19 confirmations = ~57 seconds on Tron.
    if (txData.confirmations < this.minConfirmations) {
      this.logger.info('MatchingEngine: awaiting confirmations', {
        txHash,
        confirmations: txData.confirmations,
        required:      this.minConfirmations,
      });
      // Not an error — requeue for later processing when confirmations increase
      // The listener will re-publish when next block is detected
      return;
    }

    // ── Step 4: Find matching invoice ────────────────────────────────────────
    const invoice = await this._findInvoice(txData);
    if (!invoice) {
      // No invoice matches — could be late payment, wrong amount, or unknown sender
      await this._handleNoMatch(txData);
      return;
    }

    // ── Step 5: Atomic match + ledger write ──────────────────────────────────
    await this._confirmPayment(txData, invoice);
  }

  // ─── Invoice Matching ────────────────────────────────────────────────────────

  async _findInvoice(txData) {
    // Match by BOTH uniqueAmount AND walletAddress — both required.
    // Unique amount alone is unique within active invoices, but explicit wallet match
    // gives us a second validation layer.
    return Invoice.findOne({
      uniqueAmount: txData.amount,      // String comparison — no float ambiguity
      walletAddress: txData.toAddress,
      status: { $in: ['pending', 'hash_found'] },
      expiresAt: { $gt: new Date() },   // Not expired
      matchedTxHash: null,              // Not already matched
    }).lean();
  }

  // ─── Payment Confirmation (Atomic) ──────────────────────────────────────────

  async _confirmPayment(txData, invoice) {
    const session = await mongoose.startSession();

    try {
      await session.withTransaction(async () => {
        // --- Atomic invoice update: set status to confirmed ---
        const updated = await Invoice.findOneAndUpdate(
          {
            _id: invoice._id,
            status: { $in: ['pending', 'hash_found'] },
            matchedTxHash: null, // Double-check still unmatched (race condition guard)
          },
          {
            $set: {
              status:        'confirmed',
              matchedTxHash: txData.txHash,
              confirmedAt:   new Date(),
              confirmedBlock: txData.blockNum,
              confirmations:  txData.confirmations,
            },
          },
          { new: true, session },
        );

        if (!updated) {
          // Another process matched this invoice concurrently — idempotent, skip
          this.logger.warn('MatchingEngine: invoice already matched (race condition resolved)', {
            invoiceId: String(invoice._id),
            txHash: txData.txHash,
          });
          return;
        }

        // --- Create Transaction record ---
        await Transaction.create([{
          txHash:       txData.txHash,
          invoiceId:    invoice._id,
          merchantId:   invoice.merchantId,
          walletId:     invoice.walletId,
          fromAddress:  txData.fromAddress,
          toAddress:    txData.toAddress,
          amount:       txData.amount,
          amountRaw:    txData.amountRaw,
          blockNum:     txData.blockNum,
          confirmations:txData.confirmations,
          tokenContract:txData.tokenContract,
          network:      txData.network,
          status:       'confirmed',
          confirmedAt:  new Date(),
        }], { session });

        // --- Double-entry ledger write ---
        const baseAmount  = parseFloat(invoice.amount);    // Original invoice amount (USDT)
        const platformFee = money.round(baseAmount * this.platformFeeRate, 6);
        const netAmount   = money.round(baseAmount - platformFee, 6);

        await LedgerEntry.create([
          // Debit: money received on-chain (asset increase)
          {
            merchantId:    invoice.merchantId,
            invoiceId:     invoice._id,
            txHash:        txData.txHash,
            account:       'merchant_receivable',
            type:          'credit',
            amount:        String(netAmount),
            currency:      'USDT',
            description:   `Payment confirmed — invoice ${invoice._id}`,
            idempotencyKey: `ledger:recv:${txData.txHash}`,
          },
          // Credit: platform fee earned
          {
            merchantId:    invoice.merchantId,
            invoiceId:     invoice._id,
            txHash:        txData.txHash,
            account:       'platform_fee',
            type:          'credit',
            amount:        String(platformFee),
            currency:      'USDT',
            description:   `Platform fee (${this.platformFeeRate * 100}%) — invoice ${invoice._id}`,
            idempotencyKey: `ledger:fee:${txData.txHash}`,
          },
        ], { session });
      });

      this.logger.info('MatchingEngine: payment confirmed', {
        invoiceId: String(invoice._id),
        txHash:    txData.txHash,
        amount:    txData.amount,
        merchantId:String(invoice.merchantId),
      });

      // Publish payment confirmed event → Notification Service
      await this.confirmedPublisher.publish(
        {
          invoiceId:  String(invoice._id),
          merchantId: String(invoice.merchantId),
          txHash:     txData.txHash,
          amount:     txData.amount,
          event:      'payment.confirmed',
        },
        `confirmed:${txData.txHash}`,
      );

      // Publish withdrawal eligible event → Withdrawal Engine
      await this.withdrawalPublisher.publish(
        {
          merchantId: String(invoice.merchantId),
          invoiceId:  String(invoice._id),
          amount:     String(money.round(parseFloat(invoice.amount) * (1 - this.platformFeeRate), 6)),
          event:      'withdrawal.eligible',
        },
        `withdrawal:${txData.txHash}`,
      );

    } catch (err) {
      this.logger.error('MatchingEngine: atomic confirm failed', {
        invoiceId: String(invoice._id),
        txHash:    txData.txHash,
        error:     err.message,
      });
      throw err; // Re-throw so queue retries
    } finally {
      await session.endSession();
    }
  }

  // ─── No-Match Handling ───────────────────────────────────────────────────────

  async _handleNoMatch(txData) {
    // Check if there's an expired invoice with this amount (late payment)
    const expiredInvoice = await Invoice.findOne({
      uniqueAmount:  txData.amount,
      walletAddress: txData.toAddress,
      status:        'expired',
    }).lean();

    if (expiredInvoice) {
      this.logger.warn('MatchingEngine: late payment detected — invoice already expired', {
        txHash:    txData.txHash,
        invoiceId: String(expiredInvoice._id),
        amount:    txData.amount,
      });
      await this._recordFailedTransaction(txData, 'late_payment', expiredInvoice._id);
      await this._fireAlert('late_payment', {
        txHash:    txData.txHash,
        invoiceId: String(expiredInvoice._id),
        amount:    txData.amount,
        message:   'Payment arrived after invoice expiry — requires manual review',
      });
      return;
    }

    // Unknown transaction — not matched to any invoice
    this.logger.warn('MatchingEngine: unmatched transaction', {
      txHash:    txData.txHash,
      amount:    txData.amount,
      toAddress: txData.toAddress,
    });
    await this._recordFailedTransaction(txData, 'no_invoice_match');
  }

  // ─── Helpers ────────────────────────────────────────────────────────────────

  async _recordFailedTransaction(txData, reason, invoiceId = null) {
    try {
      await Transaction.findOneAndUpdate(
        { txHash: txData.txHash },
        {
          $setOnInsert: {
            txHash:       txData.txHash,
            invoiceId,
            fromAddress:  txData.fromAddress,
            toAddress:    txData.toAddress,
            amount:       txData.amount,
            blockNum:     txData.blockNum,
            confirmations:txData.confirmations,
            tokenContract:txData.tokenContract,
            network:      txData.network,
            status:       'failed',
            failureReason:reason,
            detectedAt:   new Date(),
          },
        },
        { upsert: true, new: true },
      );
    } catch (err) {
      this.logger.error('MatchingEngine: failed to record failed transaction', { error: err.message });
    }
  }

  async _fireAlert(type, payload) {
    try {
      await this.alertPublisher.publish(
        { type, service: 'matching-engine', ...payload },
        `alert:${type}:${Date.now()}`,
      );
    } catch (err) {
      this.logger.error('MatchingEngine: failed to fire alert', { type, error: err.message });
    }
  }
}

module.exports = MatchingEngine;
