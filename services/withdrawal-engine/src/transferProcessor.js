'use strict';

/**
 * @module withdrawal-engine/transferProcessor
 *
 * Wallet Transfer Processor — Internal sweeps and top-ups between our own wallets.
 *
 * FLOW:
 *   1. Consumes `xcg:transfer:process`.
 *   2. Finds WalletTransfer record (must be 'pending').
 *   3. Starts Mongo Session:
 *        - Creates LedgerEntry (internal account movements).
 *        - Updates status to 'signing'.
 *   4. Publishes to `xcg:signing:request`.
 */

const mongoose = require('mongoose');
const { WalletTransfer, LedgerEntry } = require('@xcg/database');
const { v4: uuidv4 } = require('uuid');

class TransferProcessor {
  constructor({ signingPublisher, logger }) {
    this.signingPublisher = signingPublisher;
    this.logger = logger;
  }

  async handle(data, idempotencyKey) {
    const { transferId, triggeredBy } = data;
    this.logger.info('TransferProcessor: picking up transfer', { transferId, triggeredBy });

    const transfer = await WalletTransfer.findOne({ transferId, status: 'pending' });
    if (!transfer) {
      this.logger.warn('TransferProcessor: transfer not found or not pending', { transferId });
      return;
    }

    const session = await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        // Create an internal ledger movement record.
        // For internal sweeps, we just move liability/asset between our designated operational accounts
        const debitId = `led_${uuidv4().replace(/-/g, '')}`;
        const creditId = `led_${uuidv4().replace(/-/g, '')}`;

        await LedgerEntry.create([
          {
            entryId: debitId,
            account: 'internal_transfer_outgoing', // specialized account
            type: 'debit',
            amount: transfer.amount,
            currency: transfer.token,
            counterpartEntryId: creditId,
            description: `Internal transfer sweep Out (${transfer.transferType}) - ${transfer.transferId}`,
            idempotencyKey: `ledger:trf-out:${idempotencyKey}`,
          },
          {
            entryId: creditId,
            account: 'internal_transfer_incoming', // balance neutral across system
            type: 'credit',
            amount: transfer.amount,
            currency: transfer.token,
            counterpartEntryId: debitId,
            description: `Internal transfer sweep In (${transfer.transferType}) - ${transfer.transferId}`,
            idempotencyKey: `ledger:trf-in:${idempotencyKey}`,
          }
        ], { session });

        await WalletTransfer.findByIdAndUpdate(transfer._id, {
          $set: { status: 'signing' }
        }, { session });
      });

      this.logger.info('TransferProcessor: DB logged, publishing to signing', { transferId });
    } catch (err) {
      this.logger.error('TransferProcessor: handling failed', { transferId, error: err.message });
      throw err;
    } finally {
      await session.endSession();
    }

    // Publish direct to signing
    if (this.signingPublisher) {
      await this.signingPublisher.publish({
        type:         'transfer',
        sourceId:     String(transfer._id), 
        amount:       String(transfer.amount),
        toAddress:    transfer.toAddress,
        fromAddress:  transfer.fromAddress,
        currency:     transfer.token,
        network:      transfer.network,
      }, `sign:trf:${idempotencyKey}`);
    }
  }
}

module.exports = TransferProcessor;
