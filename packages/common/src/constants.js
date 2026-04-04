'use strict';

/**
 * System-wide constants.
 * Central source of truth for magic values used across services.
 */

const ROLES = Object.freeze({
  SUPER_ADMIN: 'super_admin', // G2: Protected — cannot be modified by any admin
  ADMIN: 'admin',
  MERCHANT: 'merchant',
  SUPPORT: 'support',
});

const INVOICE_STATUS = Object.freeze({
  INITIATED:  'initiated',
  PENDING:    'pending',           // Waiting for payment
  HASH_FOUND: 'hash_found',        // TX detected on chain
  CONFIRMING: 'confirming',        // Waiting for block confirmations
  CONFIRMED:  'confirmed',         // Enough confirmations
  SUCCESS:    'success',           // Fully settled
  EXPIRED:    'expired',           // Time window passed
  FAILED:     'failed',            // Payment found but invalid
  CANCELLED:  'cancelled',         // Merchant cancelled
  UNDERPAID:  'underpaid',         // Received < expected — manual review
  OVERPAID:   'overpaid',          // Received > expected — flagged, matched at invoice amount
});

const TX_STATUS = Object.freeze({
  DETECTED: 'detected',        // Seen on chain
  MATCHED: 'matched',          // Matched to invoice
  CONFIRMED: 'confirmed',      // Sufficient confirmations
  UNMATCHED: 'unmatched',      // No matching invoice found
  UNDERPAID: 'underpaid',      // Amount less than expected
  OVERPAID: 'overpaid',        // Amount more than expected
  LATE: 'late',                // Arrived after invoice expiry
  DUPLICATE: 'duplicate',      // Already matched another tx
  MANUAL_REVIEW: 'manual_review',
});

const WITHDRAWAL_STATUS = Object.freeze({
  REQUESTED: 'requested',
  QUEUED: 'queued',
  PENDING_APPROVAL: 'pending_approval',  // High-value, needs admin
  APPROVED: 'approved',
  SIGNING: 'signing',
  BROADCAST: 'broadcast',
  CONFIRMING: 'confirming',
  COMPLETED: 'completed',
  FAILED: 'failed',
  REJECTED: 'rejected',
});

const DISPUTE_STATUS = Object.freeze({
  OPENED: 'opened',
  MERCHANT_RESPONDED: 'merchant_responded',
  UNDER_REVIEW: 'under_review',
  RESOLVED_REFUND: 'resolved_refund',
  RESOLVED_NO_REFUND: 'resolved_no_refund',
  CLOSED: 'closed',
});

const WEBHOOK_EVENTS = Object.freeze({
  PAYMENT_CREATED: 'payment.created',
  PAYMENT_DETECTED: 'payment.detected',
  PAYMENT_CONFIRMED: 'payment.confirmed',
  PAYMENT_FAILED: 'payment.failed',
  PAYMENT_EXPIRED: 'payment.expired',
  WITHDRAWAL_COMPLETED: 'withdrawal.completed',
  WITHDRAWAL_FAILED: 'withdrawal.failed',
  DISPUTE_OPENED: 'dispute.opened',
  DISPUTE_RESOLVED: 'dispute.resolved',
});

const WEBHOOK_DELIVERY_STATUS = Object.freeze({
  PENDING: 'pending',
  DELIVERED: 'delivered',
  FAILED: 'failed',
  RETRYING: 'retrying',
});

const LEDGER_ACCOUNTS = Object.freeze({
  HOT_WALLET_INCOMING: 'hot_wallet_incoming', // Funds received on-chain (debit side of inflow)
  MERCHANT_RECEIVABLE: 'merchant_receivable',  // Money owed to merchant (net of fees)
  PLATFORM_FEE:        'platform_fee',         // Platform revenue
  MERCHANT_WITHDRAWAL: 'merchant_withdrawal',  // Money sent out to merchant
  DISPUTE_HOLD:        'dispute_hold',         // Funds frozen under dispute
  SYSTEM_RESERVE:      'system_reserve',       // System reserve fund
});

const LEDGER_ENTRY_TYPE = Object.freeze({
  DEBIT: 'debit',
  CREDIT: 'credit',
});

const AUDIT_ACTIONS = Object.freeze({
  // Auth
  AUTH_LOGIN_SUCCESS: 'auth.login.success',
  AUTH_LOGIN_FAILED: 'auth.login.failed',
  AUTH_LOGOUT: 'auth.logout',
  AUTH_REGISTER: 'auth.register',
  AUTH_2FA_ENABLED: 'auth.2fa.enabled',
  AUTH_2FA_DISABLED: 'auth.2fa.disabled',
  AUTH_PASSWORD_CHANGED: 'auth.password.changed',
  AUTH_ACCOUNT_LOCKED: 'auth.account.locked',
  AUTH_ACCOUNT_UNLOCKED: 'auth.account.unlocked',

  // Merchant
  MERCHANT_CREATED: 'merchant.created',
  MERCHANT_UPDATED: 'merchant.updated',
  MERCHANT_DISABLED: 'merchant.disabled',
  MERCHANT_API_KEY_CREATED: 'merchant.apikey.created',
  MERCHANT_API_KEY_REVOKED: 'merchant.apikey.revoked',
  MERCHANT_WEBHOOK_UPDATED: 'merchant.webhook.updated',

  // Wallet
  WALLET_ADDED: 'wallet.added',
  WALLET_DISABLED: 'wallet.disabled',
  WALLET_KEY_ACCESSED: 'wallet.key.accessed',

  // Invoice
  INVOICE_CREATED: 'invoice.created',
  INVOICE_CANCELLED: 'invoice.cancelled',
  INVOICE_EXPIRED: 'invoice.expired',

  // Transaction
  TX_DETECTED: 'transaction.detected',
  TX_MATCHED: 'transaction.matched',
  TX_CONFIRMED: 'transaction.confirmed',
  TX_FAILED: 'transaction.failed',
  TX_MANUAL_REVIEW: 'transaction.manual_review',

  // Withdrawal
  WITHDRAWAL_REQUESTED: 'withdrawal.requested',
  WITHDRAWAL_APPROVED: 'withdrawal.approved',
  WITHDRAWAL_REJECTED: 'withdrawal.rejected',
  WITHDRAWAL_COMPLETED: 'withdrawal.completed',
  WITHDRAWAL_FAILED: 'withdrawal.failed',

  // Dispute
  DISPUTE_OPENED: 'dispute.opened',
  DISPUTE_RESPONDED: 'dispute.responded',
  DISPUTE_RESOLVED: 'dispute.resolved',

  // Admin
  CONFIG_CHANGED: 'config.changed',
  USER_ROLE_CHANGED: 'user.role.changed',
  USER_DISABLED: 'user.disabled',

  // System
  SYSTEM_STARTUP: 'system.startup',
  SYSTEM_SHUTDOWN: 'system.shutdown',
  RECONCILIATION_RUN: 'reconciliation.run',
  RECONCILIATION_MISMATCH: 'reconciliation.mismatch',
});

const AUTH = Object.freeze({
  MAX_FAILED_ATTEMPTS: 5,           // Lock account after this many failures
  MAX_SESSIONS_PER_USER: 5,         // Concurrent refresh token sessions
  PASSWORD_HISTORY_SIZE: 5,         // Reject reuse of last N passwords
  BCRYPT_ROUNDS: 12,                // Default bcrypt salt rounds
  TOTP_CODE_LENGTH: 6,              // TOTP code digits
  REFRESH_TOKEN_GRACE_PERIOD: 86400, // TTL auto-delete grace (seconds)
  NONCE_TTL_SECONDS: 300,           // Anti-replay nonce window (5 min)
  TIMESTAMP_TOLERANCE_SECONDS: 30,  // API request timestamp tolerance
});

const TRON = Object.freeze({
  MAINNET_USDT_CONTRACT: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',
  SHASTA_USDT_CONTRACT: 'TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs',
  USDT_DECIMALS: 6,
  CONFIRMATIONS_REQUIRED: 19,
  BLOCK_TIME_MS: 3000,
  ENERGY_PER_TRC20_TRANSFER: 65000,
});

module.exports = {
  ROLES,
  AUTH,
  INVOICE_STATUS,
  TX_STATUS,
  WITHDRAWAL_STATUS,
  DISPUTE_STATUS,
  WEBHOOK_EVENTS,
  WEBHOOK_DELIVERY_STATUS,
  LEDGER_ACCOUNTS,
  LEDGER_ENTRY_TYPE,
  AUDIT_ACTIONS,
  TRON,
};
