'use strict';

/**
 * @module matching-engine/invoiceExpiry
 *
 * Invoice Expiry Scanner — P0 Gap Fix.
 *
 * Runs every 60 seconds. Marks all PENDING/HASH_FOUND invoices
 * whose expiresAt < now as EXPIRED.
 *
 * WHY THIS EXISTS:
 *   Without this, expired invoices stay PENDING indefinitely.
 *   The matching engine will keep trying to match them even after they expire
 *   because it filters on expiresAt > now at query time — but the status
 *   stays PENDING. More critically: the unique amount slot is NEVER released,
 *   meaning that over time every amount slot becomes permanently blocked.
 *
 * ALSO: fires payment.expired webhook event for each expired invoice
 *       so merchants know the payment window has closed.
 */

const { Invoice } = require('@xcg/database');
const { INVOICE_STATUS } = require('@xcg/common').constants;

const SCAN_INTERVAL_MS = 60_000;   // Every 60 seconds
const BATCH_SIZE       = 100;      // Process 100 at a time, never lock the DB

class InvoiceExpiryScanner {
  /**
   * @param {object} opts
   * @param {object} opts.expiredPublisher - Publisher for PAYMENT_FAILED queue (triggers webhook)
   * @param {object} opts.logger
   */
  constructor({ expiredPublisher, logger }) {
    this.expiredPublisher = expiredPublisher;
    this.logger           = logger;
    this._timer           = null;
  }

  start() {
    this.logger.info('InvoiceExpiryScanner: starting (every 60s)');
    this._scheduleNext();
  }

  stop() {
    if (this._timer) clearTimeout(this._timer);
    this.logger.info('InvoiceExpiryScanner: stopped');
  }

  _scheduleNext() {
    this._timer = setTimeout(async () => {
      await this._scan().catch((err) =>
        this.logger.error('InvoiceExpiryScanner: scan failed', { error: err.message }),
      );
      this._scheduleNext();
    }, SCAN_INTERVAL_MS);
  }

  async _scan() {
    const now = new Date();

    // Find all invoices that have expired but are still in an active state
    const EXPIRABLE_STATUSES = [
      INVOICE_STATUS.INITIATED,
      INVOICE_STATUS.PENDING,
      INVOICE_STATUS.HASH_FOUND,
    ];

    let processed = 0;

    // Process in batches to avoid locking the DB
    while (true) {
      const expiredInvoices = await Invoice.find({
        status:    { $in: EXPIRABLE_STATUSES },
        expiresAt: { $lt: now },
      })
        .select('_id invoiceId merchantId baseAmount callbackUrl')
        .limit(BATCH_SIZE)
        .lean();

      if (expiredInvoices.length === 0) break;

      // Bulk update to EXPIRED (only update ones still in expirable state — safe re-run)
      const ids = expiredInvoices.map((i) => i._id);
      const result = await Invoice.updateMany(
        {
          _id:    { $in: ids },
          status: { $in: EXPIRABLE_STATUSES }, // Guard: don't overwrite confirmed/etc
        },
        { $set: { status: INVOICE_STATUS.EXPIRED } },
      );

      this.logger.info('InvoiceExpiryScanner: expired batch', {
        totalFound: expiredInvoices.length,
        actuallyExpired: result.modifiedCount,
      });

      // Fire payment.expired event for each (so notification service sends webhook)
      for (const invoice of expiredInvoices) {
        await this._fireExpiredEvent(invoice);
      }

      processed += result.modifiedCount;

      // If fewer than batch returned, we're done
      if (expiredInvoices.length < BATCH_SIZE) break;
    }

    if (processed > 0) {
      this.logger.info(`InvoiceExpiryScanner: scan complete — ${processed} invoices expired`);
    }
  }

  async _fireExpiredEvent(invoice) {
    try {
      await this.expiredPublisher.publish(
        {
          event:      'payment.expired',
          invoiceId:  String(invoice._id),
          merchantId: String(invoice.merchantId),
          amount:     String(invoice.baseAmount),
          callbackUrl:invoice.callbackUrl || '',
          expiredAt:  new Date().toISOString(),
        },
        `expired:${String(invoice._id)}`,
      );
    } catch (err) {
      this.logger.error('InvoiceExpiryScanner: failed to fire expired event', {
        invoiceId: invoice.invoiceId, error: err.message,
      });
    }
  }
}

module.exports = InvoiceExpiryScanner;
