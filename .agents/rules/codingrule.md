---
trigger: always_on
---

This is a commercial, bank-grade payment system that will handle real money.

never use && and all comaands in single command in git. it alwasy failed with error. alway use single seperate command for each step

mern stack (use .jsx, not .ts), always follow @Description.txt
git repository : https://github.com/xpandats/xcoingateway.git
credentials : (configured locally — never commit tokens to repo)
landing page: https://github.com/xpandats/xcoingateway

no compromise with security, services, performance, scalability, structure, architechture, speed etc.
bank grade safe and security required.

1. Architecture — Monorepo with Shared Core
All 7 services in one monorepo using npm workspaces:

KEEP ARCHITECTURE CLEAN FROM DAY 1
Shared packages for encryption, DB models, logging, error handling
Each service is independently deployable but shares common utilities
Consistent code quality, single CI/CD pipeline
Easier to maintain for a small team vs 7 separate repos
2. Security — Non-Negotiable Foundation
Before ANY business logic, these must be rock solid:

Key Management — AES-256-GCM encryption for private keys, master key from ENV, key never in memory longer than needed, zeroed after use
Auth — JWT with short-lived access tokens (15 min) + secure refresh tokens (HTTP-only cookies), bcrypt with high salt rounds
API Security — HMAC-SHA256 signature on every merchant API request, nonce + timestamp to prevent replay, per-key rate limiting
RBAC — Strict role isolation (admin, merchant, support) with permission matrices
Audit Logs — Append-only, immutable, every sensitive action logged with actor, timestamp, IP, action, and before/after state
Input Validation — Every single input sanitized and validated at the edge, before touching any business logic
3. Build Order — What Actually Makes Sense
For a real payment system, the order should be:

Phase 1 — Foundation (must be bulletproof)
Database models & migrations
Authentication & RBAC
Encryption utilities
Logging & audit system
Error handling framework
Config management (per environment)


Phase 2 — Core Payment Flow
Wallet management (admin adds wallets, encrypted key storage)
Invoice/Payment creation (unique amount generation)
Blockchain Listener (Tron network only for MVP, architecture must be chain-agnostic for future scaling)
Matching Engine (the heart of the system)
Transaction lifecycle management

Phase 3 — Money Movement
Sweep Engine (NOT needed for MVP — Tron-only means payments are already in USDT TRC20, no conversion needed)
Withdrawal Engine (USDT TRC20 → merchant wallet)
Ledger system (double-entry accounting)

Phase 4 — Merchant Experience
Webhook/notification service
Merchant API (REST endpoints)
Dispute & refund system

Phase 5 — Operations
Admin dashboard API
Monitoring & alerting
Gas fee management
Fraud detection (velocity limits, risk scoring)




////

⚙️ NETWORK STRATEGY
MVP: Tron network only (USDT TRC20)
- Payments accepted in USDT TRC20 only
- No token conversion/sweep needed for MVP (already in USDT)
- Settlement in USDT TRC20
- Blockchain monitoring via TronGrid free API + public Tron RPC
- Zero budget — all services must be free tier
- Architecture MUST be chain-agnostic so future chains plug in easily

⚙️ FUTURE SWEEP SYSTEM (when multi-chain added)
Sweep Engine
 ├── Provider 1 (ChangeNOW — no KYC, low fees)
 ├── Provider 2 (SimpleSwap — no KYC, backup)
 ├── Provider 3 (Future)


⚠️ GOLDEN RULES (VERY IMPORTANT)
1. NEVER BUILD EVERYTHING AT ONCE

Your current plan = 6–12 months system
Your MVP = 2–3 weeks core

2. SECURITY BEFORE FEATURES

Every feature must answer:

"Can this be exploited?"

3. USE TESTNET FIRST (ALWAYS)
Break system on testnet
Simulate:
wrong amounts
delayed tx
duplicate tx
4. INTERNAL LEDGER IS NON-NEGOTIABLE

Without it:

You will lose track of funds
Refunds will break
Disputes impossible
5. KEEP ARCHITECTURE CLEAN FROM DAY 1

Start with:

/services
  payment
  wallet
  blockchain
  ledger
  withdrawal

NOT:

/controllers/mixedEverything.js ❌
6. LOG EVERYTHING

If something breaks and you don't have logs:
→ you're blind

7. FAIL SAFE, NOT FAST
If unsure → block transaction
Never assume success







////
┌─────────────────────────────────────────────────────┐
│  ZONE 1 — PUBLIC (Internet-facing)                  │
│  ┌───────────────┐                                  │
│  │  API Gateway   │ ← Only entry point              │
│  │  (Nginx/Kong)  │   Rate limit, WAF, IP filter,   │
│  │                │   TLS termination, request       │
│  │                │   validation BEFORE app sees it  │
│  └───────┬───────┘                                  │
└──────────┼──────────────────────────────────────────┘
           │ (only authenticated, validated traffic)
┌──────────┼──────────────────────────────────────────┐
│  ZONE 2 — APPLICATION (Business Logic)              │
│          ▼                                          │
│  ┌──────────────┐    ┌──────────────────┐           │
│  │  API Server   │    │ Notification Svc  │          │
│  │  (Auth, RBAC, │    │ (Webhooks, Alerts)│          │
│  │   Merchant,   │    └──────────────────┘           │
│  │   Invoices)   │                                   │
│  └──────┬───────┘    ┌──────────────────┐           │
│         │            │ Blockchain        │           │
│         │            │ Listener          │           │
│  ┌──────┴───────┐    │ (TronGrid polling)│           │
│  │  Matching     │    └──────────────────┘           │
│  │  Engine       │                                   │
│  │  + Ledger     │    ┌──────────────────┐           │
│  └──────────────┘    │ Withdrawal        │           │
│                      │ Processor         │           │
│                      │ (queue + validate)│           │
│                      └────────┬──────────┘           │
└───────────────────────────────┼──────────────────────┘
                                │ (signing requests only)
┌───────────────────────────────┼──────────────────────┐
│  ZONE 3 — SECURE VAULT (Maximum Isolation)           │
│                               ▼                      │
│  ┌─────────────────────────────────────────┐         │
│  │  Transaction Signing Service             │        │
│  │  ─────────────────────────────           │        │
│  │  • NO HTTP endpoint                      │        │
│  │  • Listens ONLY on internal queue        │        │
│  │  • Decrypts key → signs → zeroes memory  │        │
│  │  • Private keys NEVER leave this service │        │
│  │  • Separate process, separate user,      │        │
│  │    separate permissions                  │        │
│  └─────────────────────────────────────────┘         │
│                                                      │
│  ┌─────────────────────────────────────────┐         │
│  │  Key Vault                               │        │
│  │  ─────────────────────────────           │        │
│  │  • AES-256-GCM encrypted keys            │        │
│  │  • Master key from ENV (never in DB)     │        │
│  │  • Key derivation per wallet             │        │
│  │  • Access logged + rate-limited          │        │
│  └─────────────────────────────────────────┘         │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│  ZONE 4 — DATA (No direct external access)           │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │ MongoDB   │  │  Redis    │  │ Audit Log Store   │  │
│  │ (encrypted│  │ (queues,  │  │ (append-only,     │  │
│  │  at rest) │  │  cache)   │  │  immutable,       │  │
│  │           │  │           │  │  separate DB)     │  │
│  └──────────┘  └──────────┘  └───────────────────┘  │
└──────────────────────────────────────────────────────┘