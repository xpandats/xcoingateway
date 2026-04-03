'use strict';

/**
 * @module matching-engine/engine
 *
 * Matching Engine — Heart of XCoinGateway.
 * Uses INVOICE_STATUS constants throughout — not string literals.
 */

const mongoose   = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const { Invoice, Transaction, LedgerEntry } = require('@xcg/database');
const { money }  = require('@xcg/common');
const { INVOICE_STATUS } = require('@xcg/common').constants;

// ─── HARDCODED CONSTANTS — NEVER from config/env ─────────────────────────────
const USDT_CONTRACTS = new Set([
  'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t', // Mainnet USDT
  'TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj', // Nile testnet USDT
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

  async handle(txData, idempotencyKey) {
    const { txHash } = txData;

    // Idempotency guard
    const existingTx = await Transaction.findOne({ txHash }).select('status').lean();
    if (existingTx) {
      this.logger.debug('MatchingEngine: idempotency — already processed', { txHash });
      return;
    }

    this.logger.info('MatchingEngine: processing', {
      txHash, amount: txData.amount, toAddress: txData.toAddress, confirmations: txData.confirmations,
    });

    // 1. Contract whitelist
    if (!USDT_CONTRACTS.has(txData.tokenContract)) {
      this.logger.warn('MatchingEngine: rejected — unknown contract', { txHash, contract: txData.tokenContract });
      await this._recordFailed(txData, 'invalid_token_contract');
      return;
    }

    // 2. Symbol check
    if (txData.tokenSymbol !== 'USDT') {
      this.logger.warn('MatchingEngine: rejected — not USDT', { txHash });
      await this._recordFailed(txData, 'invalid_token_symbol');
      return;
    }

    // 3. Confirmation depth — ZERO TOLERANCE
    if (txData.confirmations < this.minConfirmations) {
      this.logger.info('MatchingEngine: awaiting confirmations', {
        txHash, have: txData.confirmations, need: this.minConfirmations,
      });
      return;
    }

    // 4. Find matching invoice using constants
    const invoice = await Invoice.findOne({
      uniqueAmount:  parseFloat(txData.amount),
      walletAddress: txData.toAddress,
      status:        { $in: [INVOICE_STATUS.PENDING, INVOICE_STATUS.HASH_FOUND] },
      expiresAt:     { $gt: new Date() },
      txHash:        null,
    }).lean();

    if (!invoice) {
      await this._handleNoMatch(txData);
      return;
    }

    await this._confirmPayment(txData, invoice);
  }

  async _confirmPayment(txData, invoice) {
    const session = await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        // Atomic: update invoice only if still in matching state
        const updated = await Invoice.findOneAndUpdate(
          {
            _id:    invoice._id,
            status: { $in: [INVOICE_STATUS.PENDING, INVOICE_STATUS.HASH_FOUND] },
            txHash: null,
          },
          {
            $set: {
              status:      INVOICE_STATUS.CONFIRMED,    // ← constant
              txHash:      txData.txHash,
              confirmedAt: new Date(),
              paidAt:      new Date(),
            },
          },
          { new: true, session },
        );

        if (!updated) {
          this.logger.warn('MatchingEngine: race condition — invoice already matched', {
            invoiceId: String(invoice._id), txHash: txData.txHash,
          });
          return;
        }

        // Record transaction
        await Transaction.create([{
          txHash:               txData.txHash,
          network:              txData.network || 'tron',
          blockNumber:          txData.blockNum || txData.blockNumber || 0,
          blockTimestamp:       txData.timestamp ? new Date(txData.timestamp * 1000) : new Date(),
          fromAddress:          txData.fromAddress,
          toAddress:            txData.toAddress,
          amount:               parseFloat(txData.amount),
          tokenContract:        txData.tokenContract,
          tokenSymbol:          'USDT',
          status:               'confirmed',
          matchedInvoiceId:     invoice._id,
          matchedAt:            new Date(),
          confirmations:        txData.confirmations,
          requiredConfirmations:this.minConfirmations,
          confirmedAt:          new Date(),
          detectedAt:           txData.detectedAt ? new Date(txData.detectedAt) : new Date(),
        }], { session });

        // Double-entry ledger (atomic)
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
            description:        `Payment received — ${invoice.invoiceId}`,
            idempotencyKey:     `ledger:recv:${txData.txHash}`,
            balanceAfter:       0,
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
            description:        `Platform fee ${(this.platformFeeRate * 100).toFixed(1)}% — ${invoice.invoiceId}`,
            idempotencyKey:     `ledger:fee:${txData.txHash}`,
            balanceAfter:       0,
          },
        ], { session });
      });

      this.logger.info('MatchingEngine: payment CONFIRMED', {
        invoiceId: invoice.invoiceId, txHash: txData.txHash,
        amount: txData.amount, merchantId: String(invoice.merchantId),
      });

      // Emit to notification service
      await this.confirmedPublisher.publish({
        event:      'payment.confirmed',
        invoiceId:  String(invoice._id),
        merchantId: String(invoice.merchantId),
        txHash:     txData.txHash,
        amount:     String(invoice.baseAmount),
        netAmount:  String(money.round(invoice.baseAmount * (1 - this.platformFeeRate), 6)),
        callbackUrl:invoice.callbackUrl || '',
        confirmedAt:new Date().toISOString(),
      }, `confirmed:${txData.txHash}`);

      // Queue for withdrawal eligibility check
      await this.withdrawalPublisher.publish({
        merchantId: String(invoice.merchantId),
        invoiceId:  String(invoice._id),
        amount:     String(money.round(invoice.baseAmount * (1 - this.platformFeeRate), 6)),
      }, `withdrawal:${txData.txHash}`);

    } catch (err) {
      this.logger.error('MatchingEngine: confirm failed', {
        invoiceId: String(invoice._id), txHash: txData.txHash, error: err.message,
      });
      throw err;
    } finally {
      await session.endSession();
    }
  }

  async _handleNoMatch(txData) {
    const expired = await Invoice.findOne({
      uniqueAmount:  parseFloat(txData.amount),
      walletAddress: txData.toAddress,
      status:        INVOICE_STATUS.EXPIRED,   // ← constant
    }).lean();

    if (expired) {
      this.logger.warn('MatchingEngine: LATE PAYMENT on expired invoice', {
        txHash: txData.txHash, invoiceId: String(expired._id),
      });
      await this._recordFailed(txData, 'late_payment', expired._id);
      await this._fireAlert('late_payment', {
        txHash: txData.txHash, invoiceId: String(expired._id),
        amount: txData.amount,
        message: 'Late payment on expired invoice — manual refund review required',
      });
      return;
    }

    this.logger.warn('MatchingEngine: no matching invoice', {
      txHash: txData.txHash, amount: txData.amount, toAddress: txData.toAddress,
    });
    await this._recordFailed(txData, 'no_invoice_match');
  }

  async _recordFailed(txData, reason, invoiceId = null) {
    try {
      await Transaction.findOneAndUpdate(
        { txHash: txData.txHash },
        {
          $setOnInsert: {
            txHash: txData.txHash, network: txData.network || 'tron',
            blockNumber: txData.blockNum || txData.blockNumber || 0,
            blockTimestamp: new Date(), fromAddress: txData.fromAddress,
            toAddress: txData.toAddress, amount: parseFloat(txData.amount),
            tokenContract: txData.tokenContract, tokenSymbol: txData.tokenSymbol || 'USDT',
            status: 'failed', matchResult: reason, matchedInvoiceId: invoiceId,
            confirmations: txData.confirmations,
            requiredConfirmations: this.minConfirmations,
            detectedAt: new Date(),
            flaggedForReview: reason === 'late_payment',
          },
        },
        { upsert: true, new: true },
      );
    } catch (err) {
      this.logger.error('MatchingEngine: failed to record TX', { error: err.message });
    }
  }

  async _fireAlert(type, payload) {
    try {
      await this.alertPublisher.publish(
        { type, service: 'matching-engine', ...payload },
        `alert:${type}:${Date.now()}`,
      );
    } catch { /* never crash matching engine */ }
  }
}

module.exports = MatchingEngine;
