'use strict';

/**
 * @module withdrawal-engine/settlementProcessor
 *
 * Settlement Processor — Triggers the start of a settlement withdrawal.
 * 
 * Consumes `xcg:settlement:process` queue and publishes to `xcg:withdrawal:eligible`.
 * The Withdrawal Processor will handle the daily limits, cooling off periods,
 * and distributed locking before creating the actual `Withdrawal` document.
 */

const { Settlement } = require('@xcg/database');
const { QUEUES } = require('@xcg/queue');

class SettlementProcessor {
  /**
   * @param {object} opts
   * @param {object} opts.logger
   * @param {object} opts.withdrawalPublisher - publishes to WITHDRAWAL_ELIGIBLE
   */
  constructor({ logger, withdrawalPublisher }) {
    this.logger = logger;
    this.withdrawalPublisher = withdrawalPublisher;
  }

  async handle(data, idempotencyKey) {
    const { settlementId } = data;

    this.logger.info('SettlementProcessor: picking up settlement', { settlementId });

    const settlement = await Settlement.findOne({ settlementId, status: 'pending' }).lean();
    if (!settlement) {
      this.logger.warn('SettlementProcessor: settlement not found or not pending', { settlementId });
      return;
    }

    // Pass the settlement request directly to the standard withdrawal pipeline.
    // The processor.js has been modified to handle data.settlementId and 
    // link the generated Withdrawal directly to this Settlement inside its lock.
    await this.withdrawalPublisher.publish({
      merchantId: String(settlement.merchantId),
      settlementId: String(settlement._id),
      amount: String(settlement.netAmount), // Request the net amount to be withdrawn
    }, `wdl:stl:${settlementId}:${Date.now()}`);

    this.logger.info('SettlementProcessor: dispatched settlement to withdrawal eligible queue', { settlementId });
  }
}

module.exports = SettlementProcessor;
