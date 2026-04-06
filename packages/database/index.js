'use strict';

const { connectDB, disconnectDB, isDBConnected } = require('./src/connection');
const { connectAuditDB, disconnectAuditDB, getAuditConnection } = require('./src/auditConnection');

// ─── Core Models ─────────────────────────────────────────────────────────────
const User              = require('./src/models/User');
const Merchant          = require('./src/models/Merchant');
const MerchantBalance   = require('./src/models/MerchantBalance');
const Wallet            = require('./src/models/Wallet');
const WalletAssignment  = require('./src/models/WalletAssignment');
const Invoice           = require('./src/models/Invoice');
const Transaction       = require('./src/models/Transaction');
const LedgerEntry       = require('./src/models/LedgerEntry');

// ─── Payment Flow Models ─────────────────────────────────────────────────────
const PaymentSession    = require('./src/models/PaymentSession');
const Settlement        = require('./src/models/Settlement');
const Refund            = require('./src/models/Refund');

// ─── Withdrawal & Fund Movement ──────────────────────────────────────────────
const Withdrawal        = require('./src/models/Withdrawal');
const WalletTransfer    = require('./src/models/WalletTransfer');
const GasFeeRecord      = require('./src/models/GasFeeRecord');
const EnergyStake       = require('./src/models/EnergyStake');

// ─── Dispute & Compliance ────────────────────────────────────────────────────
const Dispute           = require('./src/models/Dispute');
const BlacklistedWallet = require('./src/models/BlacklistedWallet');
const IpBlocklist       = require('./src/models/IpBlocklist');
const FraudEvent        = require('./src/models/FraudEvent');

// ─── Audit & Logging ─────────────────────────────────────────────────────────
const AuditLog          = require('./src/models/AuditLog');
const ApiRequestLog     = require('./src/models/ApiRequestLog');
const NotificationRecord = require('./src/models/NotificationRecord');
const LoginEvent        = require('./src/models/LoginEvent');
const KeyRotationLog    = require('./src/models/KeyRotationLog');

// ─── Notifications ───────────────────────────────────────────────────────────
const WebhookDelivery   = require('./src/models/WebhookDelivery');

// ─── Configuration & System ──────────────────────────────────────────────────
const SystemConfig      = require('./src/models/SystemConfig');
const ReconciliationReport = require('./src/models/ReconciliationReport');
const BlockScanCursor   = require('./src/models/BlockScanCursor');
const ServiceHealthSnapshot = require('./src/models/ServiceHealthSnapshot');
const DeadLetterEntry   = require('./src/models/DeadLetterEntry');

// ─── Auth & Security ─────────────────────────────────────────────────────────
const RefreshToken      = require('./src/models/RefreshToken');
const UsedTotpCode      = require('./src/models/UsedTotpCode');
const UsedNonce         = require('./src/models/UsedNonce');

module.exports = {
  // Connections
  connectDB,
  disconnectDB,
  isDBConnected,
  // Separate INSERT-ONLY audit connection (#1 mainnet requirement)
  connectAuditDB,
  disconnectAuditDB,
  getAuditConnection,

  // ─── Models (33 total) ───────────────────────────────────────────────────
  // Core
  User,
  Merchant,
  MerchantBalance,
  Wallet,
  WalletAssignment,
  Invoice,
  Transaction,
  LedgerEntry,
  // Payment flow
  PaymentSession,
  Settlement,
  Refund,
  // Withdrawal & fund movement
  Withdrawal,
  WalletTransfer,
  GasFeeRecord,
  EnergyStake,
  // Dispute & compliance
  Dispute,
  BlacklistedWallet,
  IpBlocklist,
  FraudEvent,
  // Audit & logging
  AuditLog,
  ApiRequestLog,
  NotificationRecord,
  LoginEvent,
  KeyRotationLog,
  // Notifications
  WebhookDelivery,
  // Configuration & system
  SystemConfig,
  ReconciliationReport,
  BlockScanCursor,
  ServiceHealthSnapshot,
  DeadLetterEntry,
  // Auth & security
  RefreshToken,
  UsedTotpCode,
  UsedNonce,
};
