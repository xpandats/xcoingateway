'use strict';

/**
 * @module withdrawal-engine/server
 * Entry point for the Withdrawal Engine.
 */

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env.local') });

const { config, validateConfig }               = require('../../api-server/src/config');
const { connectDB }                             = require('@xcg/database');
const { Withdrawal, AuditLog, Wallet, Refund, WalletTransfer }          = require('@xcg/database');
const { createLogger }                          = require('@xcg/logger');
const { createConsumer, createPublisher, createDLQMonitor, QUEUES } = require('@xcg/queue');
const { startHealthServer }                     = require('@xcg/common/src/healthServer');
const { createRedisClient }                     = require('@xcg/common/src/redisFactory');
const { registerShutdown, runMain }             = require('@xcg/common/src/shutdown');
const mongoose                                  = require('mongoose');


const TronAdapter                               = require('@xcg/tron').TronAdapter;
const WithdrawalProcessor                       = require('./processor');
const SettlementProcessor                       = require('./settlementProcessor');
const RefundProcessor                           = require('./refundProcessor');
const TransferProcessor                         = require('./transferProcessor');
const WithdrawalConfirmationTracker             = require('./withdrawalConfirmationTracker');
const RefundConfirmationTracker                 = require('./refundConfirmationTracker');
const TransferConfirmationTracker               = require('./transferConfirmationTracker');

const logger = createLogger('withdrawal-engine');

async function main() {
  logger.info('WithdrawalEngine: starting up');

  try { validateConfig(); } catch (err) {
    logger.error('WithdrawalEngine: config validation failed', { error: err.message });
    process.exit(1);
  }

  await connectDB(config.db.uri, logger);

  const redis = createRedisClient({ logger }); // Gap 5: Sentinel/Cluster-aware
  redis.on('error', (err) => logger.error('WithdrawalEngine: Redis error', { error: err.message }));


  // Health check server (internal only — port 3094)
  startHealthServer({ port: 3094, service: 'withdrawal-engine', mongoose, redis, logger });

  const redisOpts = {
    host: new URL(config.redis.url).hostname,
    port: Number(new URL(config.redis.url).port) || 6379,
  };

  const signingPublisher  = createPublisher(QUEUES.SIGNING_REQUEST,      redisOpts, config.queue.signingSecret, logger);
  const alertPublisher    = createPublisher(QUEUES.SYSTEM_ALERT,          redisOpts, config.queue.signingSecret, logger);
  // Self-publisher: allows processor to re-queue cooling-off withdrawals with BullMQ delay
  const selfPublisher     = createPublisher(QUEUES.WITHDRAWAL_ELIGIBLE,   redisOpts, config.queue.signingSecret, logger);
  // Confirmation publisher: sends withdrawal.completed events → notification service → merchant webhook
  // Reuses PAYMENT_CONFIRMED queue (notification service already consumes it for generic event dispatch)
  const confirmationPublisher = createPublisher(QUEUES.PAYMENT_CONFIRMED, redisOpts, config.queue.signingSecret, logger);

  // Tron adapter for energy checks
  const tronAdapter = new TronAdapter({
    network: config.tron.network,
    apiKey:  config.tron.apiKey,
  }, logger);

  const processor = new WithdrawalProcessor({
    signingPublisher,
    alertPublisher,
    tronAdapter,
    config:      config.wallet,
    tronNetwork: config.tron.network,
    logger,
    redis,       // H3: needed for per-merchant distributed lock
  });

  const settlementProcessor = new SettlementProcessor({ logger, withdrawalPublisher: selfPublisher });
  const refundProcessor = new RefundProcessor({ redis, signingPublisher, alertPublisher, logger });
  const transferProcessor = new TransferProcessor({ signingPublisher, logger });

  // ── H1 FIX: Startup recovery for withdrawals stuck in 'signing' status ──────
  // Scenario: service crashed after publishing to signing:request queue,
  // but before the signing:complete consumer could update status to 'broadcast'.
  // On restart, we find these stuck withdrawals and check the audit log:
  //   - If audit log has a successful signing (txHash exists) → broadcast already happened
  //     → update status to 'broadcast' + alert admin to verify on-chain
  //   - If no audit log entry for this withdrawal → signing may not have started
  //     → reset to 'processing' for re-processing + alert admin
  // This runs ONCE at startup before workers begin consuming.
  try {
    const STUCK_THRESHOLD_MS = 10 * 60 * 1000; // 10 minutes
    const stuckCutoff = new Date(Date.now() - STUCK_THRESHOLD_MS);
    const stuckWithdrawals = await Withdrawal.find({
      status:    'signing',
      updatedAt: { $lt: stuckCutoff },
    }).select('_id withdrawalId merchantId amount').lean();

    if (stuckWithdrawals.length > 0) {
      logger.warn('WithdrawalEngine: found stuck SIGNING withdrawals on startup — running recovery', {
        count: stuckWithdrawals.length,
      });

      for (const wdl of stuckWithdrawals) {
        // Check audit log for a successful signing operation for this withdrawal
        const auditEntry = await AuditLog.findOne({
          action:     'signing_operation',
          resourceId: String(wdl._id),
          outcome:    'success',
        }).select('metadata.txHash').lean();

        if (auditEntry?.metadata?.txHash) {
          // Signing succeeded — update status to broadcast + alert admin to verify
          await Withdrawal.findByIdAndUpdate(wdl._id, {
            $set: {
              status:      'broadcast',
              txHash:      auditEntry.metadata.txHash,
              broadcastAt: new Date(),
              reviewNotes: 'RECOVERY: Status recovered from stuck signing state on restart. Verify on-chain.',
            },
          });
          logger.warn('WithdrawalEngine: recovery — updated stuck signing → broadcast (txHash found in audit)', {
            withdrawalId: wdl.withdrawalId, txHash: auditEntry.metadata.txHash,
          });
          await alertPublisher.publish(
            {
              type: 'stuck_signing_recovery_broadcast',
              withdrawalId: wdl.withdrawalId, txHash: auditEntry.metadata.txHash,
              message: `Withdrawal ${wdl.withdrawalId} was stuck in 'signing' but audit log shows successful broadcast. Status updated to 'broadcast'. Verify on-chain.`,
            },
            `alert:recovery:${wdl.withdrawalId}`,
          ).catch(() => {});
        } else {
          // No audit entry — signing may not have completed — reset to processing
          await Withdrawal.findByIdAndUpdate(wdl._id, {
            $set: {
              status:      'processing',
              reviewNotes: 'RECOVERY: Status reset from stuck signing state on restart. No audit log found. Will be re-queued.',
            },
          });
          logger.warn('WithdrawalEngine: recovery — reset stuck signing → processing (no audit log)', {
            withdrawalId: wdl.withdrawalId,
          });
          await alertPublisher.publish(
            {
              type: 'stuck_signing_recovery_reset',
              withdrawalId: wdl.withdrawalId,
              message: `Withdrawal ${wdl.withdrawalId} was stuck in 'signing' with no audit log. Reset to 'processing'. Check signing service logs.`,
            },
            `alert:recovery:reset:${wdl.withdrawalId}`,
          ).catch(() => {});
        }
      }
    }
  } catch (recoveryErr) {
    // Never let recovery failure block startup — log + alert
    logger.error('WithdrawalEngine: startup recovery failed', { error: recoveryErr.message });
  }

  // Also listen for signing:complete to update withdrawal status
  // Note: signingCompletePublisher below is now confirmationPublisher — renamed for clarity
  // We do NOT publish payment.confirmed from here — that queue is for incoming payments.
  // Instead, the confirmation tracker will publish withdrawal.completed to PAYMENT_CONFIRMED
  // (notification service's webhookDispatch handler is event-type agnostic).

  // Start withdrawal confirmation tracker (polls Tron for broadcast withdrawal confirmations)
  const confirmationTracker = new WithdrawalConfirmationTracker({
    tronAdapter,
    confirmedPublisher: confirmationPublisher,
    alertPublisher,
    minConfirmations:   config.tron.confirmationsRequired || 19, // Default: 19 blocks (~1 min on Tron)
    logger,
  });
  await confirmationTracker.start();

  const refundTracker = new RefundConfirmationTracker({
    tronAdapter,
    confirmedPublisher: confirmationPublisher,
    alertPublisher,
    minConfirmations: config.tron.confirmationsRequired || 19,
    logger,
  });
  await refundTracker.start();

  const transferTracker = new TransferConfirmationTracker({
    tronAdapter,
    alertPublisher,
    minConfirmations: config.tron.confirmationsRequired || 19,
    logger,
  });
  await transferTracker.start();

  const { worker: eligibleWorker } = createConsumer(
    QUEUES.WITHDRAWAL_ELIGIBLE,
    redisOpts,
    config.queue.signingSecret,
    logger,
    (data, idempotencyKey) => processor.handle(data, idempotencyKey, selfPublisher), // Pass self-publisher
    { concurrency: 2 }, // Low concurrency — withdrawal is a critical path
  );

  const { worker: signingCompleteWorker } = createConsumer(
    QUEUES.SIGNING_COMPLETE,
    redisOpts,
    config.queue.signingSecret,
    logger,
    async (data) => {
      // M2 FIX: Proper error handling + correct status transition
      // C1 companion: now that signing-service includes withdrawalId, this works correctly
      if (!data.success || !data.txHash || !data.withdrawalId) {
        logger.warn('WithdrawalEngine: signing:complete message missing required fields', {
          hasSuccess: !!data.success, hasTxHash: !!data.txHash, hasWithdrawalId: !!data.withdrawalId,
        });
        return;
      }

      try {
        const type = data.type || 'withdrawal';

        if (type === 'withdrawal') {
          const updated = await Withdrawal.findOneAndUpdate(
            { _id: data.withdrawalId, status: 'signing' }, // Only update if still in signing state
            { $set: { status: 'broadcast', txHash: data.txHash, broadcastAt: new Date() } },
            { new: true },
          );

          if (!updated) {
            logger.info('WithdrawalEngine: signing:complete — withdrawal already updated (idempotent)', {
              withdrawalId: data.withdrawalId, txHash: data.txHash,
            });
            return;
          }

          logger.info('WithdrawalEngine: withdrawal broadcast confirmed', {
            withdrawalId: data.withdrawalId, txHash: data.txHash,
          });

          confirmationTracker.track(String(updated._id), data.txHash, {
            withdrawalId: updated.withdrawalId,
            merchantId:   String(updated.merchantId),
            amount:       String(updated.amount),
            toAddress:    updated.toAddress,
          });
        }
        else if (type === 'refund') {
          // Re-using withdrawalId as generic sourceId/documentId from the signing payload
          const updated = await Refund.findOneAndUpdate(
            { _id: data.withdrawalId, status: 'signing' },
            { $set: { status: 'broadcast', txHash: data.txHash, broadcastAt: new Date() } },
            { new: true }
          );
          if (!updated) return;
          logger.info('WithdrawalEngine: refund broadcast confirmed', { refundId: updated.refundId, txHash: data.txHash });
          refundTracker.track(String(updated._id), data.txHash, {
            refundId: updated.refundId, merchantId: String(updated.merchantId), amount: String(updated.refundAmount), toAddress: updated.toAddress,
          });
        }
        else if (type === 'transfer') {
          // Re-using withdrawalId as generic sourceId/documentId
          const updated = await WalletTransfer.findOneAndUpdate(
            { _id: data.withdrawalId, status: 'signing' },
            { $set: { status: 'broadcast', txHash: data.txHash, broadcastAt: new Date() } },
            { new: true }
          );
          if (!updated) return;
          logger.info('WithdrawalEngine: transfer broadcast confirmed', { transferId: updated.transferId, txHash: data.txHash });
          transferTracker.track(String(updated._id), data.txHash, {
            transferId: updated.transferId, amount: String(updated.amount), toAddress: updated.toAddress,
          });
        }

      } catch (err) {
        logger.error('WithdrawalEngine: signing:complete consumer failed to update withdrawal', {
          withdrawalId: data.withdrawalId, txHash: data.txHash, error: err.message,
        });
        await alertPublisher.publish(
          {
            type: 'signing_complete_update_failed',
            withdrawalId: data.withdrawalId, txHash: data.txHash,
            message: `Failed to update withdrawal ${data.withdrawalId} to 'broadcast' status. Manual intervention required. TxHash: ${data.txHash}`,
          },
          `alert:signing-complete-fail:${data.withdrawalId}`,
        ).catch(() => {});
        throw err; // Re-throw so BullMQ retries
      }
    },
    { concurrency: 5 },
  );

  const { worker: settlementWorker } = createConsumer(QUEUES.SETTLEMENT_PROCESS, redisOpts, config.queue.signingSecret, logger, (data, id) => settlementProcessor.handle(data, id), { concurrency: 2 });
  const { worker: refundWorker } = createConsumer(QUEUES.REFUND_PROCESS, redisOpts, config.queue.signingSecret, logger, (data, id) => refundProcessor.handle(data, id), { concurrency: 2 });
  const { worker: transferWorker } = createConsumer(QUEUES.TRANSFER_PROCESS, redisOpts, config.queue.signingSecret, logger, (data, id) => transferProcessor.handle(data, id), { concurrency: 1 });

  // M3 FIX: DLQ monitor — alerts on dead letter queue messages
  const dlqMonitor = createDLQMonitor({
    redisOpts,
    secret:         config.queue.signingSecret,
    alertPublisher,
    serviceName:    'withdrawal-engine',
    logger,
  });

  // ── GAS FEE MONITOR: Proactive Tron energy check every 30 minutes ────────────
  // Per-withdrawal energy checks are REACTIVE (only checks when processing).
  // This monitor is PROACTIVE — fires admin alert BEFORE a batch of withdrawals hits empty energy.
  const GAS_CHECK_INTERVAL_MS = 30 * 60 * 1000; // 30 minutes
  let gasMonitorTimer;

  async function checkWalletEnergy() {
    try {
      const hotWallets = await Wallet.find({ isActive: true, type: { $in: ['hot', 'receiving'] } })
        .select('_id address label')
        .lean();

      for (const wallet of hotWallets) {
        try {
          const hasSufficientEnergy = await tronAdapter.hasSufficientEnergy(wallet.address);
          if (!hasSufficientEnergy) {
            logger.warn('WithdrawalEngine: GAS MONITOR — low Tron energy detected', {
              walletAddress: wallet.address,
              walletId:      String(wallet._id),
            });
            await alertPublisher.publish(
              {
                type:          'low_tron_energy',
                walletAddress: wallet.address,
                walletId:      String(wallet._id),
                walletLabel:   wallet.label || 'unnamed',
                service:       'withdrawal-engine',
                message: `Hot wallet ${wallet.address} has insufficient Tron energy. Withdrawals from this wallet will be deferred until energy is replenished. Please stake TRX or purchase energy.`,
              },
              `alert:low_energy:${wallet.address}:${Date.now()}`,
            );
          }
        } catch (walletErr) {
          // Never let one wallet check failure abort the entire monitor
          logger.error('WithdrawalEngine: gas monitor failed for wallet', {
            address: wallet.address, error: walletErr.message,
          });
        }
      }
    } catch (err) {
      logger.error('WithdrawalEngine: gas monitor cycle failed', { error: err.message });
    } finally {
      // Reschedule (unless shutting down)
      gasMonitorTimer = setTimeout(checkWalletEnergy, GAS_CHECK_INTERVAL_MS);
    }
  }

  // Run first check after 2 minutes (let service fully start first)
  gasMonitorTimer = setTimeout(checkWalletEnergy, 2 * 60 * 1000);
  logger.info('WithdrawalEngine: gas fee monitor started — first check in 2 minutes, then every 30 minutes');

  registerShutdown({
    logger,
    service: 'withdrawal-engine',
    cleanup: async () => {
      clearTimeout(gasMonitorTimer);
      confirmationTracker.stop();
      refundTracker.stop();
      transferTracker.stop();
      dlqMonitor.stop();
      await eligibleWorker.close();
      await signingCompleteWorker.close();
      await settlementWorker.close();
      await refundWorker.close();
      await transferWorker.close();
      await redis.quit();
    },
  });

  logger.info('WithdrawalEngine: running');
}

runMain(main, { logger, service: 'withdrawal-engine' });

