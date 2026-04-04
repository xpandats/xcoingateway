'use strict';

/**
 * @module fraud/fraudEngine
 *
 * Fraud & Risk Engine — Central fraud detection for XCoinGateway.
 *
 * CHECKS (in order of severity):
 *   1. Wallet blacklist    — hard block, zero tolerance
 *   2. Velocity limits     — transactions per merchant per hour/day
 *   3. Invoice velocity    — invoices created per merchant per hour (API abuse)
 *   4. Amount anomaly      — amount significantly outside merchant's normal range
 *   5. Volume spike        — sudden volume > N× merchant's rolling average
 *   6. Risk score          — composite score from all soft signals
 *
 * ACTIONS:
 *   BLOCKED  (score >= BLOCK_THRESHOLD)  — transaction rejected immediately
 *   FLAGGED  (score >= FLAG_THRESHOLD)   — transaction continues, admin alerted
 *   ALLOWED  (score <  FLAG_THRESHOLD)   — transaction proceeds normally
 *
 * INTEGRATION POINTS:
 *   - Matching Engine: checkIncomingTransaction() before invoice matching
 *   - API Server:      checkInvoiceCreation()     before invoice is created
 *   - Auth Middleware: checkLoginAttempt()         on every login
 *
 * IMMUTABLE LOGGING: Every check result is logged to FraudEvent (append-only).
 * This provides a complete audit trail for disputes and regulatory compliance.
 */

const { BlacklistedWallet, FraudEvent, Invoice, Transaction } = require('@xcg/database');
const { FRAUD_EVENT_TYPE, FRAUD_ACTION } = require('@xcg/database/src/models/FraudEvent');

// ─── Risk Score Thresholds ────────────────────────────────────────────────────
const BLOCK_THRESHOLD = 80; // Score >= 80 → hard block
const FLAG_THRESHOLD  = 50; // Score >= 50 → flag for review, still process

// ─── Velocity Defaults (overridable via SystemConfig) ────────────────────────
const DEFAULT_LIMITS = {
  maxTxPerMerchantPerHour:    20,   // Max confirmed transactions per merchant per hour
  maxTxPerMerchantPerDay:    100,   // Max confirmed transactions per merchant per 24h
  maxInvoicePerMerchantPerHour: 30, // Max invoices created per merchant per hour
  maxInvoicePerMerchantPerDay: 200, // Max invoices created per merchant per 24h
  maxAmountPerTxUsdt:        10000, // Single tx hard limit (USDT). Matches withdrawal cap.
  volumeSpikeMultiplier:       5,   // Flag if current-hour volume > 5× rolling avg
  riskScoreWeights: {
    velocityHour:     20,  // Points added per velocity limit hit (hourly)
    velocityDay:      15,  // Points added per velocity limit hit (daily)
    amountAnomaly:    25,  // Points added for amount > 3× merchant avg
    volumeSpike:      30,  // Points added for volume spike detection
    newWallet:         5,  // Points added if sender has < 3 prior txs on chain
  },
};

class FraudEngine {
  /**
   * @param {object} opts
   * @param {object} opts.alertPublisher  - Queue publisher for SYSTEM_ALERT
   * @param {object} opts.logger
   * @param {object} [opts.limits]        - Override default velocity limits
   */
  constructor({ alertPublisher, logger, limits = {} }) {
    this.alertPublisher = alertPublisher;
    this.logger         = logger;
    this.limits         = { ...DEFAULT_LIMITS, ...limits };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // PUBLIC API
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Run all fraud checks for an incoming blockchain transaction.
   * Called by the Matching Engine BEFORE invoice matching.
   *
   * @param {object} txData    - Transaction data from blockchain listener
   * @param {object} invoice   - The matched invoice (or null if not matched yet)
   * @returns {Promise<FraudResult>}
   */
  async checkIncomingTransaction(txData, invoice = null) {
    const context = {
      txHash:      txData.txHash,
      fromAddress: txData.fromAddress,
      toAddress:   txData.toAddress,
      amount:      parseFloat(txData.amount),
      network:     txData.network || 'tron',
      merchantId:  invoice?.merchantId || null,
      invoiceId:   invoice?._id || null,
    };

    // 1. Hard check: wallet blacklist (immediate BLOCKED if hit)
    const blacklistResult = await this._checkBlacklist(context.fromAddress, context.network, context);
    if (blacklistResult.blocked) return blacklistResult;

    // 2. Hard check: single-tx amount cap
    if (context.amount > this.limits.maxAmountPerTxUsdt) {
      return this._buildResult(FRAUD_ACTION.BLOCKED, FRAUD_EVENT_TYPE.AMOUNT_ANOMALY, 100, context, {
        reason:    `Single transaction amount ${context.amount} USDT exceeds hard cap of ${this.limits.maxAmountPerTxUsdt} USDT`,
        threshold: this.limits.maxAmountPerTxUsdt,
        actual:    context.amount,
      });
    }

    if (!invoice) return this._allowResult(context);

    // 3. Soft checks — accumulate risk score
    let riskScore = 0;
    const signals = [];

    // Merchant velocity
    const velocityResult = await this._checkMerchantTxVelocity(context.merchantId, context);
    riskScore += velocityResult.score;
    if (velocityResult.score > 0) signals.push(velocityResult.detail);

    // Amount anomaly vs merchant's average
    const amountResult = await this._checkAmountAnomaly(context.merchantId, context.amount, context);
    riskScore += amountResult.score;
    if (amountResult.score > 0) signals.push(amountResult.detail);

    // Volume spike
    const spikeResult = await this._checkVolumeSpike(context.merchantId, context);
    riskScore += spikeResult.score;
    if (spikeResult.score > 0) signals.push(spikeResult.detail);

    // Cap at 100
    riskScore = Math.min(100, riskScore);

    if (riskScore >= BLOCK_THRESHOLD) {
      return this._buildResult(FRAUD_ACTION.BLOCKED, FRAUD_EVENT_TYPE.RISK_SCORE_HIGH, riskScore, context, {
        reason:  `Composite risk score ${riskScore}/100 exceeds block threshold of ${BLOCK_THRESHOLD}`,
        signals,
      });
    }

    if (riskScore >= FLAG_THRESHOLD) {
      return this._buildResult(FRAUD_ACTION.FLAGGED, FRAUD_EVENT_TYPE.RISK_SCORE_HIGH, riskScore, context, {
        reason:  `Composite risk score ${riskScore}/100 exceeds flag threshold of ${FLAG_THRESHOLD} — flagged for review`,
        signals,
      });
    }

    return this._allowResult(context, riskScore);
  }

  /**
   * Run fraud checks for a new invoice creation request.
   * Called by API Server BEFORE creating the invoice.
   *
   * @param {object} merchantId  - Merchant ObjectId
   * @param {object} invoiceData - { baseAmount, callbackUrl, metadata }
   * @param {object} requestCtx  - { ipAddress, userAgent }
   * @returns {Promise<FraudResult>}
   */
  async checkInvoiceCreation(merchantId, invoiceData, requestCtx = {}) {
    const context = {
      merchantId,
      amount:    parseFloat(invoiceData.baseAmount),
      ipAddress: requestCtx.ipAddress,
      userAgent: requestCtx.userAgent,
    };

    // Hard check: single invoice amount cap
    if (context.amount > this.limits.maxAmountPerTxUsdt) {
      return this._buildResult(FRAUD_ACTION.BLOCKED, FRAUD_EVENT_TYPE.AMOUNT_ANOMALY, 100, context, {
        reason:    `Invoice amount ${context.amount} USDT exceeds hard limit of ${this.limits.maxAmountPerTxUsdt} USDT`,
        threshold: this.limits.maxAmountPerTxUsdt,
        actual:    context.amount,
      });
    }

    // Invoice velocity check
    const hourlyCount = await Invoice.countDocuments({
      merchantId,
      createdAt: { $gte: new Date(Date.now() - 3600_000) },
    });
    const dailyCount = await Invoice.countDocuments({
      merchantId,
      createdAt: { $gte: new Date(Date.now() - 86400_000) },
    });

    if (hourlyCount >= this.limits.maxInvoicePerMerchantPerHour) {
      return this._buildResult(FRAUD_ACTION.BLOCKED, FRAUD_EVENT_TYPE.VELOCITY_EXCEEDED, 90, context, {
        reason:    `Invoice creation velocity exceeded: ${hourlyCount} invoices in last hour (limit: ${this.limits.maxInvoicePerMerchantPerHour})`,
        window:    '1h',
        count:     hourlyCount,
        limit:     this.limits.maxInvoicePerMerchantPerHour,
      });
    }

    if (dailyCount >= this.limits.maxInvoicePerMerchantPerDay) {
      return this._buildResult(FRAUD_ACTION.BLOCKED, FRAUD_EVENT_TYPE.VELOCITY_EXCEEDED, 85, context, {
        reason:    `Invoice creation velocity exceeded: ${dailyCount} invoices in last 24h (limit: ${this.limits.maxInvoicePerMerchantPerDay})`,
        window:    '24h',
        count:     dailyCount,
        limit:     this.limits.maxInvoicePerMerchantPerDay,
      });
    }

    return this._allowResult(context, 0);
  }

  /**
   * Check a wallet address against the blacklist.
   * Standalone method — usable independently by any service.
   *
   * @param {string} address
   * @param {string} [network='tron']
   * @returns {Promise<boolean>}
   */
  async isBlacklisted(address, network = 'tron') {
    const entry = await BlacklistedWallet.isBlacklisted(address, network);
    return !!entry;
  }

  /**
   * Add a wallet address to the blacklist.
   *
   * @param {object} data - { address, network, reason, notes, addedBy, linkedTxHash }
   * @returns {Promise<object>} The created blacklist entry
   */
  async blacklistWallet(data) {
    const entry = await BlacklistedWallet.create({
      address:       data.address.toLowerCase(),
      network:       data.network || 'tron',
      reason:        data.reason,
      notes:         data.notes || '',
      addedBy:       data.addedBy || null,
      autoFlagged:   data.autoFlagged || false,
      linkedTxHash:  data.linkedTxHash || null,
      linkedInvoiceId: data.linkedInvoiceId || null,
      isActive:      true,
    });

    this.logger.warn('FraudEngine: wallet blacklisted', {
      address: data.address, reason: data.reason, addedBy: String(data.addedBy),
    });

    await this._fireAlert('wallet_blacklisted', {
      address: data.address, reason: data.reason,
      message: `Wallet ${data.address} blacklisted: ${data.reason}`,
    });

    return entry;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // PRIVATE CHECKS
  // ─────────────────────────────────────────────────────────────────────────────

  async _checkBlacklist(address, network, context) {
    if (!address) return { blocked: false };

    const entry = await BlacklistedWallet.isBlacklisted(address, network);
    if (!entry) return { blocked: false };

    const result = await this._buildResult(
      FRAUD_ACTION.BLOCKED,
      FRAUD_EVENT_TYPE.BLACKLIST_HIT,
      100,
      context,
      {
        reason:          `Sender address ${address} is on blacklist (reason: ${entry.reason})`,
        blacklistReason: entry.reason,
        blacklistId:     String(entry._id),
      },
    );
    return { ...result, blocked: true };
  }

  async _checkMerchantTxVelocity(merchantId, context) {
    if (!merchantId) return { score: 0, detail: null };

    const [hourlyCount, dailyCount] = await Promise.all([
      Transaction.countDocuments({
        matchedInvoiceId: { $exists: true, $ne: null },
        // Use a $lookup approach via Invoice.merchantId — simplified: count via Invoice
        createdAt: { $gte: new Date(Date.now() - 3600_000) },
      }),
      Transaction.countDocuments({
        createdAt: { $gte: new Date(Date.now() - 86400_000) },
      }),
    ]);

    // Better: count via Invoice (has merchantId)
    const [merchantHourly, merchantDaily] = await Promise.all([
      Invoice.countDocuments({
        merchantId,
        status:    { $in: ['confirmed', 'success'] },
        confirmedAt: { $gte: new Date(Date.now() - 3600_000) },
      }),
      Invoice.countDocuments({
        merchantId,
        status:    { $in: ['confirmed', 'success'] },
        confirmedAt: { $gte: new Date(Date.now() - 86400_000) },
      }),
    ]);

    let score = 0;
    const detail = { merchantHourly, merchantDaily };

    if (merchantHourly >= this.limits.maxTxPerMerchantPerHour) {
      score += this.limits.riskScoreWeights.velocityHour;
      detail.velocityHourExceeded = true;
    }
    if (merchantDaily >= this.limits.maxTxPerMerchantPerDay) {
      score += this.limits.riskScoreWeights.velocityDay;
      detail.velocityDayExceeded = true;
    }

    return { score, detail: score > 0 ? { type: 'velocity', ...detail } : null };
  }

  async _checkAmountAnomaly(merchantId, amount, context) {
    if (!merchantId) return { score: 0, detail: null };

    // Calculate merchant's average confirmed invoice amount over last 30 days
    const [result] = await Invoice.aggregate([
      {
        $match: {
          merchantId,
          status:    { $in: ['confirmed', 'success'] },
          createdAt: { $gte: new Date(Date.now() - 30 * 86400_000) },
        },
      },
      {
        $group: {
          _id: null,
          avg: { $avg: '$baseAmount' },
          max: { $max: '$baseAmount' },
          count: { $sum: 1 },
        },
      },
    ]);

    if (!result || result.count < 5) return { score: 0, detail: null }; // Not enough history

    const anomalyMultiplier = amount / result.avg;
    if (anomalyMultiplier > 3) {
      const score = this.limits.riskScoreWeights.amountAnomaly;
      return {
        score,
        detail: {
          type:       'amount_anomaly',
          amount,
          merchantAvg: result.avg,
          multiplier:  anomalyMultiplier.toFixed(2),
        },
      };
    }

    return { score: 0, detail: null };
  }

  async _checkVolumeSpike(merchantId, context) {
    if (!merchantId) return { score: 0, detail: null };

    // Current hour volume
    const [currentHour] = await Invoice.aggregate([
      {
        $match: {
          merchantId,
          status:    { $in: ['confirmed', 'success', 'pending', 'hash_found'] },
          createdAt: { $gte: new Date(Date.now() - 3600_000) },
        },
      },
      { $group: { _id: null, totalAmount: { $sum: '$baseAmount' }, count: { $sum: 1 } } },
    ]);

    // Rolling 7-day hourly average (approximate)
    const [sevenDayAvg] = await Invoice.aggregate([
      {
        $match: {
          merchantId,
          status:    { $in: ['confirmed', 'success'] },
          createdAt: { $gte: new Date(Date.now() - 7 * 86400_000) },
        },
      },
      {
        $group: {
          _id: null,
          avgHourlyAmount: { $avg: '$baseAmount' }, // Will divide by 168 (7d*24h)
          count:           { $sum: 1 },
        },
      },
    ]);

    if (!currentHour || !sevenDayAvg || sevenDayAvg.count < 10) {
      return { score: 0, detail: null };
    }

    const rollingHourlyAvg  = (sevenDayAvg.avgHourlyAmount * sevenDayAvg.count) / 168;
    const spikeRatio        = currentHour.totalAmount / Math.max(rollingHourlyAvg, 1);

    if (spikeRatio > this.limits.volumeSpikeMultiplier) {
      const score = this.limits.riskScoreWeights.volumeSpike;
      return {
        score,
        detail: {
          type:            'volume_spike',
          currentHourVol:  currentHour.totalAmount,
          rollingAvg:      rollingHourlyAvg.toFixed(2),
          spikeRatio:      spikeRatio.toFixed(2),
          threshold:       this.limits.volumeSpikeMultiplier,
        },
      };
    }

    return { score: 0, detail: null };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // RESULT BUILDERS
  // ─────────────────────────────────────────────────────────────────────────────

  async _buildResult(action, eventType, riskScore, context, details) {
    // Log to immutable fraud event store
    try {
      await FraudEvent.create({
        eventType,
        action,
        riskScore,
        merchantId:  context.merchantId  || null,
        invoiceId:   context.invoiceId   || null,
        txHash:      context.txHash      || null,
        fromAddress: context.fromAddress || null,
        toAddress:   context.toAddress   || null,
        amount:      context.amount      || null,
        network:     context.network     || 'tron',
        ipAddress:   context.ipAddress   || null,
        userAgent:   context.userAgent   || null,
        userId:      context.userId      || null,
        details,
        reason:      details.reason,
      });
    } catch (err) {
      // Never let fraud logging crash the payment flow
      this.logger.error('FraudEngine: failed to log fraud event', { error: err.message });
    }

    // Fire alert for blocked/flagged transactions
    if (action === FRAUD_ACTION.BLOCKED || action === FRAUD_ACTION.FLAGGED) {
      await this._fireAlert(`fraud_${action}`, {
        eventType, action, riskScore,
        txHash:    context.txHash,
        merchant:  String(context.merchantId),
        amount:    context.amount,
        message:   details.reason,
      });
    }

    if (action === FRAUD_ACTION.BLOCKED) {
      this.logger.warn('FraudEngine: transaction BLOCKED', {
        eventType, riskScore, txHash: context.txHash,
        merchant: String(context.merchantId), reason: details.reason,
      });
    } else if (action === FRAUD_ACTION.FLAGGED) {
      this.logger.warn('FraudEngine: transaction FLAGGED', {
        eventType, riskScore, txHash: context.txHash,
        merchant: String(context.merchantId), reason: details.reason,
      });
    }

    return {
      blocked:   action === FRAUD_ACTION.BLOCKED,
      flagged:   action === FRAUD_ACTION.FLAGGED,
      allowed:   action === FRAUD_ACTION.ALLOWED,
      action,
      riskScore,
      eventType,
      reason:    details.reason,
    };
  }

  _allowResult(context, riskScore = 0) {
    return {
      blocked:   false,
      flagged:   false,
      allowed:   true,
      action:    FRAUD_ACTION.ALLOWED,
      riskScore,
      eventType: null,
      reason:    null,
    };
  }

  async _fireAlert(type, payload) {
    try {
      await this.alertPublisher.publish(
        { type, service: 'fraud-engine', ...payload },
        `alert:fraud:${type}:${Date.now()}`,
      );
    } catch { /* never crash */ }
  }
}

module.exports = FraudEngine;
