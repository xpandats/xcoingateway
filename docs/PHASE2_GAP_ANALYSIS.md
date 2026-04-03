# Phase 2 — Banking-Grade Gap Analysis
# What's missing, what's broken, what needs hardening

## CRITICAL GAPS

### 1. app.js — New routes NOT wired
- Routes registered: only /auth and /health
- Missing: /admin/wallets, /api/v1/payments, /admin/merchants, /api/v1/withdrawals

### 2. asyncHandler — Missing utility
- walletController.js and invoiceController.js reference asyncHandler
- File does not exist in utils/

### 3. adminIpCheck export name mismatch
- wallets.js: require('./middleware/adminIpCheck') → file is adminIpWhitelist.js

### 4. merchantApiAuth.js — References merchant.apiKeys.key and .secret
- Merchant model has keyHash + apiSecret (not .key and .secret)
- Full API key lookup/verification flow broken

### 5. Merchant Service — MISSING entirely
- API key generation (secure random, hashed)
- Merchant CRUD
- API key rotation/revoke
- Webhook settings management

### 6. MerchantController — MISSING entirely
- No admin merchant management endpoints

### 7. Invoice Expiry Job — MISSING
- Invoices expire but nothing sets them to 'expired' status
- Matching engine may match expired invoices

### 8. Withdrawal Request API — MISSING
- Merchants cannot request withdrawals via API
- WithdrawalController missing

### 9. walletService — references @xcg/crypto encrypt without derivationSalt pattern
- encrypt(privateKey, masterKey, derivationSalt) — signature mismatch

### 10. matching-engine — field name mismatches
- Uses txData.blockNum but Transaction model has blockNumber
- Uses matchedTxHash but Invoice model has txHash
- LedgerEntry requires entryId, counterpartEntryId, balanceAfter

### 11. packages/queue/src/queues.js — MAY NOT EXIST
- queueClient imports from './queues' but file status unknown
