'use strict';

/**
 * @module matching-engine/engine — CORRECTED
 *
 * Matching Engine — Heart of XCoinGateway.
 *
 * Corrected to match actual DB model field names:
 *   Invoice:     txHash (not matchedTxHash), walletAddress (not walletId)
 *   Transaction: blockNumber (not blockNum), matchedInvoiceId (not invoiceId)
 *   LedgerEntry: entryId required, counterpartEntryId required, amount is Number (not String)
 *
 * TRANSACTION STATE MACHINE:
 *   initiated → pending → hash_found → confirming → confirmed → success
 *            ↘ expired     ↘ failed
 *
 * MATCHING CRITERIA (ALL must pass):
 *   1. toAddress is our active wallet
 *   2. Token contract = official USDT TRC20 (hardcoded)
 *   3. tokenSymbol = 'USDT'
 *   4. Amount matches active invoice uniqueAmount (exact float match)
 *   5. Invoice not expired (expiresAt > now)
 *   6. Invoice not already matched (txHash = null)
 *   7. Confirmations >= 19 (ZERO TOLERANCE — never less)
 *   8. TX hash idempotent (unique index on Transaction.txHash)
 */

const mongoose   = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const { Invoice, Transaction, LedgerEntry } = require('@xcg/database');
const { money }  = require('@xcg/common');

// ─── HARDCODED CONSTANTS — NEVER from config/env ─────────────────────────────
const USDT_CONTRACTS = new Set([
  'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t', // Mainnet
  'TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj', // Nile testnet
]);

class MatchingEngine {
  constructor({ minConfirmations, platformFeeRate, confirmedPublisher, alertPublisher, withdrawalPublisher, logger }) {
    this.minConfirmations    = minConfirmations || 19;
    this.platformFeeRate     = platformFeeRate  || 0.001;
    this.confirmedPublisher  = confirmedPublisher;
    this.alertPublisher      = alertPublisher;
    this.withdrawalPublisher = withdrawalPublisher;
    this.logger              = logger;
  }

  // ─── Main Handler ─────────────────────────────────────────────────────────

  async handle(txData, idempotencyKey) {
    const { txHash } = txData;

    // ── Idempotency: already processed? ──────────────────────────────────────
    const existingTx = await Transaction.findOne({ txHash }).select('status').lean();
    if (existingTx) {
      this.logger.debug('MatchingEngine: already processed — skipping', { txHash, status: existingTx.status });
      return;
    }

    this.logger.info('MatchingEngine: processing', { txHash, amount: txData.amount, toAddress: txData.toAddress, confirmations: txData.confirmations });

    // ── 1. Token contract whitelist (fake token attack prevention) ────────────
    if (!USDT_CONTRACTS.has(txData.tokenContract)) {
      this.logger.warn('MatchingEngine: rejected — unknown contract', { txHash, contract: txData.tokenContract });
      await this._recordFailed(txData, 'invalid_token_contract');
      return;
    }

    // ── 2. Token symbol validation ────────────────────────────────────────────
    if (txData.tokenSymbol !== 'USDT') {
      this.logger.warn('MatchingEngine: rejected — not USDT', { txHash });
      await this._recordFailed(txData, 'invalid_token_symbol');
      return;
    }

    // ── 3. Confirmation depth (CRITICAL — never credit 0-conf) ────────────────
    if (txData.confirmations < this.minConfirmations) {
      this.logger.info('MatchingEngine: insufficient confirmations — awaiting', {
        txHash,
        have:   txData.confirmations,
        need:   this.minConfirmations,
      });
      return; // Will be re-emitted by listener on next block
    }

    // ── 4. Find matching active invoice ───────────────────────────────────────
    const invoice = await Invoice.findOne({
      uniqueAmount:  txData.amount,       // Exact float match
      walletAddress: txData.toAddress,
      status:        { $in: ['pending', 'hash_found'] },
      expiresAt:     { $gt: new Date() }, // Not expired
      txHash:        null,                // Not already matched
    }).lean();

    if (!invoice) {
      await this._handleNoMatch(txData);
      return;
    }

    // ── 5. Atomic confirm ─────────────────────────────────────────────────────
    await this._confirmPayment(txData, invoice);
  }

  // ─── Atomic Payment Confirmation ─────────────────────────────────────────────

  async _confirmPayment(txData, invoice) {
    const session = await mongoose.startSession();

    try {
      await session.withTransaction(async () => {

        // Atomic invoice status update — guard against concurrent match
        const updated = await Invoice.findOneAndUpdate(
          {
            _id:    invoice._id,
            status: { $in: ['pending', 'hash_found'] },
            txHash: null, // Double-check still unmatched
          },
          {
            $set: {
              status:       'confirmed',
              txHash:       txData.txHash,
              confirmedAt:  new Date(),
            },
          },
          { new: true, session },
        );

        if (!updated) {
          // Race condition: another process matched this invoice
          this.logger.warn('MatchingEngine: race condition resolved — already matched', {
            invoiceId: String(invoice._id),
            txHash: txData.txHash,
          });
          return;
        }

        // Create Transaction record
        await Transaction.create([{
          txHash:        txData.txHash,
          network:       txData.network || 'tron',
          blockNumber:   txData.blockNum || txData.blockNumber || 0,
          blockTimestamp:txData.timestamp ? new Date(txData.timestamp) : new Date(),
          fromAddress:   txData.fromAddress,
          toAddress:     txData.toAddress,
          amount:        parseFloat(txData.amount),
          tokenContract: txData.tokenContract,
          tokenSymbol:   txData.tokenSymbol || 'USDT',
          status:        'confirmed',
          matchedInvoiceId: invoice._id,
          matchedAt:     new Date(),
          confirmations: txData.confirmations,
          requiredConfirmations: this.minConfirmations,
          confirmedAt:   new Date(),
          detectedAt:    txData.detectedAt ? new Date(txData.detectedAt) : new Date(),
        }], { session });

        // Double-entry ledger: MUST be atomic with invoice status update
        const baseAmount  = invoice.baseAmount;
        const platformFee = money.round(baseAmount * this.platformFeeRate, 6);
        const netAmount   = money.round(baseAmount - platformFee, 6);

        const creditId    = `led_${uuidv4().replace(/-/g, '')}`;
        const feeId       = `led_${uuidv4().replace(/-/g, '')}`;

        await LedgerEntry.create([
          {
            entryId:            creditId,
            account:            'merchant_receivable',
            type:               'credit',
            amount:             netAmount,
            currency:           'USDT',
            merchantId:         invoice.merchantId,
            invoiceId:          invoice._id,
            counterpartEntryId: feeId,
            description:        `Payment received — invoice ${invoice.invoiceId}`,
            idempotencyKey:     `ledger:recv:${txData.txHash}`,
            balanceAfter:       0, // Reconciliation will verify
          },
          {
            entryId:            feeId,
            account:            'platform_fee',
            type:               'credit',
            amount:             platformFee,
            currency:           'USDT',
            merchantId:         invoice.merchantId,
            invoiceId:          invoice._id,
            counterpartEntryId: creditId,
            description:        `Platform fee (${(this.platformFeeRate * 100).toFixed(1)}%) — invoice ${invoice.invoiceId}`,
            idempotencyKey:     `ledger:fee:${txData.txHash}`,
            balanceAfter:       0,
          },
        ], { session });
      });

      this.logger.info('MatchingEngine: payment CONFIRMED + ledger written', {
        invoiceId:  String(invoice._id),
        invoiceRef: invoice.invoiceId,
        txHash:     txData.txHash,
        amount:     txData.amount,
        merchantId: String(invoice.merchantId),
      });

      // Publish confirmed event → Notification Service
      await this.confirmedPublisher.publish(
        {
          event:      'payment.confirmed',
          invoiceId:  String(invoice._id),
          merchantId: String(invoice.merchantId),
          txHash:     txData.txHash,
          amount:     String(invoice.baseAmount),
          netAmount:  String(money.round(invoice.baseAmount * (1 - this.platformFeeRate), 6)),
          callbackUrl:invoice.callbackUrl || '',
        },
        `confirmed:${txData.txHash}`,
      );

      // If merchant has auto-withdrawal enabled → queue withdrawal
      await this.withdrawalPublisher.publish(
        {
          merchantId: String(invoice.merchantId),
          invoiceId:  String(invoice._id),
          amount:     String(money.round(invoice.baseAmount * (1 - this.platformFeeRate), 6)),
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
      throw err; // Re-throw → BullMQ retries with backoff
    } finally {
      await session.endSession();
    }
  }

  // ─── No Match Handling ────────────────────────────────────────────────────────

  async _handleNoMatch(txData) {
    // Check for expired invoice (late payment)
    const expired = await Invoice.findOne({
      uniqueAmount:  txData.amount,
      walletAddress: txData.toAddress,
      status:        'expired',
    }).lean();

    if (expired) {
      this.logger.warn('MatchingEngine: LATE PAYMENT — invoice already expired', {
        txHash:    txData.txHash,
        invoiceId: String(expired._id),
        amount:    txData.amount,
      });
      await this._recordFailed(txData, 'late_payment', expired._id);
      await this._fireAlert('late_payment', {
        txHash:    txData.txHash,
        invoiceId: String(expired._id),
        amount:    txData.amount,
        message:   'Payment arrived after invoice expiry — manual review required',
      });
      return;
    }

    this.logger.warn('MatchingEngine: unmatched transaction', {
      txHash:    txData.txHash,
      amount:    txData.amount,
      toAddress: txData.toAddress,
    });
    await this._recordFailed(txData, 'no_invoice_match');
  }

  // ─── Helpers ────────────────────────────────────────────────────────────────

  async _recordFailed(txData, reason, invoiceId = null) {
    try {
      await Transaction.findOneAndUpdate(
        { txHash: txData.txHash },
        {
          $setOnInsert: {
            txHash:        txData.txHash,
            network:       txData.network || 'tron',
            blockNumber:   txData.blockNum || txData.blockNumber || 0,
            blockTimestamp:new Date(),
            fromAddress:   txData.fromAddress,
            toAddress:     txData.toAddress,
            amount:        parseFloat(txData.amount),
            tokenContract: txData.tokenContract,
            tokenSymbol:   txData.tokenSymbol || 'USDT',
            status:        'failed',
            matchResult:   reason,
            matchedInvoiceId: invoiceId,
            confirmations: txData.confirmations,
            requiredConfirmations: this.minConfirmations,
            detectedAt:    new Date(),
            flaggedForReview: reason === 'late_payment',
            reviewReason:  reason === 'late_payment' ? 'Late payment — potential refund needed' : null,
          },
        },
        { upsert: true, new: true },
      );
    } catch (err) {
      this.logger.error('MatchingEngine: failed to record rejected TX', { error: err.message });
    }
  }

  async _fireAlert(type, payload) {
    try {
      await this.alertPublisher.publish(
        { type, service: 'matching-engine', ...payload },
        `alert:${type}:${Date.now()}`,
      );
    } catch { /* never crash */ }
  }
}

module.exports = MatchingEngine;
