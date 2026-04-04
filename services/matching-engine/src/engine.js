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

        // TRUE DOUBLE-ENTRY LEDGER (3 atomic entries):
        //   1. hot_wallet_incoming:  DEBIT  full received amount (money arrived on-chain)
        //   2. merchant_receivable:  CREDIT net amount after fee (money owed to merchant)
        //   3. platform_fee:         CREDIT platform fee (our revenue)
        // This is proper accounting: Debit side = Credit side = fullAmount
        const receivedAmt  = parseFloat(txData.amount); // actual on-chain amount
        const platformFee  = money.round(receivedAmt * this.platformFeeRate, 6);
        const netAmount    = money.round(receivedAmt - platformFee, 6);

        // Calculate running balances BEFORE insert (for balanceAfter field accuracy)
        // This allows reconciliation tools to verify each entry independently
        const [merchantBalance] = await LedgerEntry.aggregate([
          { $match: { merchantId: invoice.merchantId, account: 'merchant_receivable' } },
          { $group: { _id: null, net: { $sum: { $cond: [{ $eq: ['$type', 'credit'] }, '$amount', { $multiply: ['$amount', -1] }] } } } },
        ]).session(session);
        const merchantPriorBalance = merchantBalance?.net || 0;

        const incomingId   = `led_${uuidv4().replace(/-/g, '')}`;
        const creditId     = `led_${uuidv4().replace(/-/g, '')}`;
        const feeId        = `led_${uuidv4().replace(/-/g, '')}`;

        await LedgerEntry.create([
          // DEBIT: hot wallet received this amount from the blockchain
          {
            entryId:            incomingId,
            account:            'hot_wallet_incoming',
            type:               'debit',
            amount:             receivedAmt,
            currency:           'USDT',
            merchantId:         invoice.merchantId,
            invoiceId:          invoice._id,
            counterpartEntryId: creditId,
            description:        `On-chain receipt — ${invoice.invoiceId} (${txData.txHash.slice(0,12)}...)`,
            idempotencyKey:     `ledger:incoming:${txData.txHash}`,
            balanceAfter:       receivedAmt, // hot_wallet increases by received amount
          },
          // CREDIT: net amount owed to merchant
          {
            entryId:            creditId,
            account:            'merchant_receivable',
            type:               'credit',
            amount:             netAmount,
            currency:           'USDT',
            merchantId:         invoice.merchantId,
            invoiceId:          invoice._id,
            counterpartEntryId: incomingId,
            description:        `Payment net — ${invoice.invoiceId}`,
            idempotencyKey:     `ledger:recv:${txData.txHash}`,
            balanceAfter:       money.round(merchantPriorBalance + netAmount, 6),
          },
          // CREDIT: platform fee
          {
            entryId:            feeId,
            account:            'platform_fee',
            type:               'credit',
            amount:             platformFee,
            currency:           'USDT',
            merchantId:         invoice.merchantId,
            invoiceId:          invoice._id,
            counterpartEntryId: incomingId,
            description:        `Platform fee ${(this.platformFeeRate * 100).toFixed(2)}% — ${invoice.invoiceId}`,
            idempotencyKey:     `ledger:fee:${txData.txHash}`,
            balanceAfter:       platformFee, // Simplified: use per-entry amount for fee account
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
    const amount = parseFloat(txData.amount);

    // 1. Duplicate payment check — invoice already matched for this amount+wallet
    const alreadyMatched = await Invoice.findOne({
      walletAddress: txData.toAddress,
      status:        { $in: [INVOICE_STATUS.CONFIRMED, INVOICE_STATUS.SUCCESS] },
      // Check if this tx amount is close to a recently-confirmed invoice
      uniqueAmount:  { $gte: amount - 0.01, $lte: amount + 0.01 },
    }).lean();

    if (alreadyMatched) {
      this.logger.warn('MatchingEngine: DUPLICATE PAYMENT — already matched invoice', {
        txHash: txData.txHash, invoiceId: String(alreadyMatched._id), amount,
      });
      await this._recordFailed(txData, 'duplicate_payment', alreadyMatched._id, true);
      await this._fireAlert('duplicate_payment', {
        txHash: txData.txHash, invoiceId: String(alreadyMatched._id), amount: txData.amount,
        message: `Duplicate payment detected — ${amount} USDT for already-matched invoice. Manual refund review required.`,
      });
      return;
    }

    // 2. Late payment — invoice existed but expired
    const lateMatch = await Invoice.findOne({
      uniqueAmount:  amount,
      walletAddress: txData.toAddress,
      status:        INVOICE_STATUS.EXPIRED,
    }).lean();

    if (lateMatch) {
      this.logger.warn('MatchingEngine: LATE PAYMENT on expired invoice', {
        txHash: txData.txHash, invoiceId: String(lateMatch._id),
      });
      await this._recordFailed(txData, 'late_payment', lateMatch._id, true);
      await this._fireAlert('late_payment', {
        txHash: txData.txHash, invoiceId: String(lateMatch._id), amount: txData.amount,
        message: 'Late payment on expired invoice — manual refund review required',
      });
      return;
    }

    // 3. Underpayment — find invoice for this wallet where received < uniqueAmount
    // Look for an active invoice where the received amount is less than expected (within 50%)
    const underpaidInvoice = await Invoice.findOne({
      walletAddress: txData.toAddress,
      status:        { $in: [INVOICE_STATUS.PENDING, INVOICE_STATUS.HASH_FOUND] },
      expiresAt:     { $gt: new Date() },
      uniqueAmount:  { $gt: amount, $lte: amount * 1.5 }, // Received is less than expected
    }).lean();

    if (underpaidInvoice) {
      this.logger.warn('MatchingEngine: UNDERPAYMENT detected', {
        txHash: txData.txHash, invoiceId: String(underpaidInvoice._id),
        expected: underpaidInvoice.uniqueAmount, received: amount,
      });
      await Invoice.findByIdAndUpdate(underpaidInvoice._id, {
        $set: { status: INVOICE_STATUS.UNDERPAID },
      });
      await this._recordFailed(txData, 'underpayment', underpaidInvoice._id, true);
      await this._fireAlert('underpayment', {
        txHash: txData.txHash, invoiceId: String(underpaidInvoice._id),
        amount: txData.amount, expected: String(underpaidInvoice.uniqueAmount),
        message: `Underpayment: received ${amount} USDT, expected ${underpaidInvoice.uniqueAmount} USDT. Manual review required.`,
      });
      return;
    }

    // 4. Overpayment — find invoice where received > uniqueAmount (within 10 USDT)
    const overpaidInvoice = await Invoice.findOne({
      walletAddress: txData.toAddress,
      status:        { $in: [INVOICE_STATUS.PENDING, INVOICE_STATUS.HASH_FOUND] },
      expiresAt:     { $gt: new Date() },
      uniqueAmount:  { $gte: amount * 0.9, $lt: amount }, // Received is more than expected
    }).lean();

    if (overpaidInvoice) {
      this.logger.warn('MatchingEngine: OVERPAYMENT — matching at invoice amount, flagging excess', {
        txHash: txData.txHash, invoiceId: String(overpaidInvoice._id),
        expected: overpaidInvoice.uniqueAmount, received: amount,
      });
      // Still confirm the payment for the invoice amount, but flag overpayment
      const modifiedTxData = { ...txData, amount: String(overpaidInvoice.uniqueAmount), overpaid: true, actualAmount: txData.amount };
      await this._confirmPayment(modifiedTxData, overpaidInvoice);
      await this._fireAlert('overpayment', {
        txHash: txData.txHash, invoiceId: String(overpaidInvoice._id),
        amount: txData.amount, invoiceAmount: String(overpaidInvoice.uniqueAmount),
        message: `Overpayment: received ${amount} USDT, invoice was ${overpaidInvoice.uniqueAmount} USDT. Excess refund review required.`,
      });
      return;
    }

    // 5. No match at all
    this.logger.warn('MatchingEngine: no matching invoice', {
      txHash: txData.txHash, amount: txData.amount, toAddress: txData.toAddress,
    });
    await this._recordFailed(txData, 'no_invoice_match');
  }

  async _recordFailed(txData, reason, invoiceId = null, flagForReview = false) {
    try {
      await Transaction.findOneAndUpdate(
        { txHash: txData.txHash },
        {
          $setOnInsert: {
            txHash:               txData.txHash,
            network:              txData.network || 'tron',
            blockNumber:          txData.blockNum || txData.blockNumber || 0,
            blockTimestamp:       new Date(),
            fromAddress:          txData.fromAddress,
            toAddress:            txData.toAddress,
            amount:               parseFloat(txData.amount),
            tokenContract:        txData.tokenContract,
            tokenSymbol:          txData.tokenSymbol || 'USDT',
            status:               'failed',
            matchResult:          reason,
            matchedInvoiceId:     invoiceId,
            confirmations:        txData.confirmations,
            requiredConfirmations:this.minConfirmations,
            detectedAt:           new Date(),
            flaggedForReview:     flagForReview,
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
