# XCoinGateway — Extended Security Reference — Part 2 of 3
## Domains 33–42 | INTERNAL CONFIDENTIAL

---

## DOMAIN 33 — FINANCIAL & PAYMENT SPECIFIC ATTACKS

| Attack | Description | Status | Priority |
|--------|-------------|--------|----------|
| Double crediting | Same TX hash credited twice | ❌ TX hash unique index + idempotency | 🔴 |
| Amount rounding exploit | 0.999999 rounds to 1.0 in some libs | ✅ BigInt money.js (no float rounding) | Done |
| Decimal precision manipulation | Amount 150.0000034 accepted as 150 | ✅ precision(6) in Joi + BigInt internally | Done |
| Currency confusion | Send BTC, credited as USDT | ✅ Currency and network validated | Done |
| Fake token contract | Custom TRC20 with same symbol USDT | ❌ Must validate contract address whitelist | 🔴 |
| Underpayment accepted | 149.99 credited as 150 | ❌ Matching engine must enforce exact match | 🔴 |
| Overpayment exploit | Send extra to consume unique amount | ❌ Matching: only match exact uniqueAmount | 🔴 |
| Invoice timeout bypass | Pay expired invoice | ❌ Block on-chain even if invoice expired | 🔴 |
| Partial payment split | Two txns both matching uniqueAmount | ❌ Require full amount in single txn | 🔴 |
| Dust attack | 0.000001 USDT floods wallets | ❌ Min amount validation + filter dust | 🟠 |
| Fee deduction confusion | Network fee reduces received amount | ❌ Always check received amount not sent | 🔴 |
| Replay payment cross-network | Same txn replayed on testnet/mainnet | ❌ Network ID validation per txn | 🟠 |
| Address reuse attack | Same address for multiple invoices | ✅ Unique address per invoice (design) | Done |
| Invoice ID enumeration | /invoice/1, /invoice/2 etc. | ✅ MongoDB ObjectId (not sequential) | Done |
| Merchant impersonation | Fake merchant ID in request | ✅ Server injects merchantId from JWT | Done |
| Withdrawal replay | Same withdrawal submitted twice | ❌ Idempotency key on withdrawal + hash | 🔴 |
| Withdrawal to self | Withdraw to a gateway wallet (money loop) | ❌ Validate toAddress not in own wallet pool | 🔴 |
| Withdrawal without cooling-off | Immediate large withdrawal after big deposit | ❌ 1-hour minimum hold before withdrawal | 🔴 |
| Withdrawal over daily cap | No daily limit enforcement | ❌ Per-merchant daily cap | 🔴 |
| Refund fraud (Phase 2) | Claim refund without returning funds | ❌ Dispute evidence requirement | 🟠 |
| Money laundering via layering | Multiple small withdrawals to avoid limits | ❌ Velocity detection + AML rules | 🔴🏦 |
| TRC10 vs TRC20 confusion | TRC10 USDT (different contract) accepted | ❌ Validate contract is TRC20 USDT specifically | 🔴 |
| Memo/destination tag required | Exchange requires memo; we send without | ❌ Warn merchant if target is exchange | 🟠 |
| 0-confirmation crediting | Credit before TX confirmed on blockchain | ❌ Require 19+ Tron block confirmations | 🔴 |
| Block reorganization | Confirmed TX removed from chain (reorg) | ❌ Monitor for reorgs + credit reversal | 🟠 |

---

## DOMAIN 34 — EMAIL SECURITY

> Email not yet implemented. All must be enforced when email is added.

| Control | Description | Status | Priority |
|---------|-------------|--------|----------|
| SPF record | Prevents email spoofing from our domain | ❌ DNS config | 🔴 |
| DKIM signing | Cryptographic signature on outbound email | ❌ Email provider config | 🔴 |
| DMARC policy | Enforcement of SPF+DKIM | ❌ DNS + policy: reject | 🔴 |
| SMTP injection | User input in To:/Subject: headers | ❌ Must sanitize \n\r in email fields | 🔴 |
| Email header injection | `\r\nBcc: attacker@x.com` | ❌ Same as SMTP injection | 🔴 |
| Password reset link hijacking | Link reused or no expiry | ❌ One-time tokens with 15min expiry | 🔴 |
| Reset link enumeration | Different timing for valid/invalid email | ❌ Always same response + timing | 🔴 |
| Reset link sent over HTTP | Token in plaintext request | ❌ HTTPS only + token in path not query | 🔴 |
| Email content XSS | HTML email with malicious content | ❌ Plain text emails only, no HTML | 🟠 |
| Email spoofing (lookalike domain) | xcoingateway.com vs xc0ingateway.com | ❌ Domain monitoring service | 🟡 |
| Email data exfiltration | Sensitive data in email body | ❌ Never include passwords, keys in email | 🔴 |
| Open relay | Our SMTP accepts and forwards any email | ❌ Use reputable SMTP provider (SendGrid) | 🟠 |

---

## DOMAIN 35 — WEBSOCKET & REAL-TIME SECURITY

> WebSockets planned for Phase 2 (payment status push).

| Attack | Description | Status | Priority |
|--------|-------------|--------|----------|
| WS handshake without auth | Connect to WS without JWT | ❌ Validate JWT in WS upgrade handler | 🔴 |
| WS upgrade hijacking | HTTP → WS upgrade without Origin check | ❌ Validate Origin on upgrade | 🔴 |
| WS message injection | Send arbitrary messages as authenticated user | ❌ Per-message auth + message schema | 🔴 |
| WS DoS — message flooding | 10000 msgs/sec from one connection | ❌ WS rate limiting per connection | 🔴 |
| WS DoS — slow frame | Never complete a frame | ❌ WS frame timeout | 🟠 |
| Broadcast to wrong room | Merchant A receives Merchant B events | ❌ Strict room = merchantId | 🔴 |
| WS session fixation | Upgrade using pre-auth session | ❌ Re-auth token on upgrade | 🟠 |
| Cross-site WebSocket hijacking | Attacker page opens WS to our server | ❌ Origin + CSRF token on WS | 🔴 |
| WS data exfiltration | Continuous stream of sensitive data | ❌ Rate limit push events per connection | 🟠 |
| JWT expiry not enforced in WS | WS stays open after token expires | ❌ Re-validate JWT periodically in WS | 🔴 |

---

## DOMAIN 36 — MULTI-TENANCY SECURITY

| Attack | Description | Status | Priority |
|--------|-------------|--------|----------|
| Cross-tenant data access | Merchant A reads Merchant B invoices | ✅ ownershipFilter enforced on all queries | Done |
| Tenant ID manipulation | Tamper merchantId in request body | ✅ Server injects merchantId from JWT | Done |
| Admin read across tenants | Admin endpoint exposes all merchants | ✅ RBAC admin permission set | Done |
| Shared Redis namespace | RateLimit key collision between merchants | ⚠️ Keys include IP; need merchantId in key too | 🟠 |
| Shared log correlation | Grep shows all tenants' data | ✅ merchantId in every log entry | Done |
| Tenant enumeration | /api/v1/merchant/1, /merchant/2 | ✅ ObjectId opaque IDs | Done |
| Shared DB collection name | All invoices in one collection (intended, secured by filter) | ✅ Always filtered by merchantId | Done |
| Webhook URL collision | Two merchants same webhook URL | ✅ Per-merchant webhook secret | Done |
| Noisy neighbor (resource exhaustion) | One merchant floods others | ✅ Per-merchant rate limiting | Done |
| Shared signing key across merchants | One compromised key breaks all | ✅ Per-merchant API key + webhook secret | Done |

---

## DOMAIN 37 — BROWSER SECURITY (DEEP)

| Attack | Status | Priority |
|--------|--------|----------|
| Clickjacking (iframe embed) | ✅ frameAncestors:'none' in CSP | Done |
| Content sniffing (MIME confusion) | ✅ X-Content-Type-Options:nosniff | Done |
| HTML5 sandbox escape | ❌ Frontend responsibility | 🟠 |
| Speculative fetch / prefetch | ❌ No Prefetch-Control header yet | 🟡 |
| Cross-origin resource timing attack | ❌ Timing-Allow-Origin not set | 🟡 |
| Referrer leakage to third parties | ✅ Referrer-Policy:strict-origin | Done |
| Browser autofill data theft | ❌ autocomplete=off on payment fields (frontend) | 🟠 |
| Credential manager autofill to wrong domain | ❌ FIDO2 domain binding (frontend) | 🟠 |
| Clipboard hijacking (fake address) | ❌ Bitcoin address copy replacement detection | 🟠 |
| WebRTC IP leakage | ❌ Block WebRTC if not needed (Permissions-Policy) | ✅ permissions-policy done | Done |
| SharedArrayBuffer (Spectre exploit) | ✅ crossOriginEmbedderPolicy: false (set to true if needed) | 🟡 |
| window.opener hijacking | ❌ rel="noopener noreferrer" in all links (frontend) | 🟠 |
| postMessage to wrong origin | ❌ Always validate origin in addEventListener | 🔴 |
| localStorage sensitive data | ❌ Never store tokens in localStorage (frontend) | 🔴 |
| Service Worker scope hijacking | ❌ Strict scope in SW registration | 🟠 |
| DNS rebinding via browser | ✅ SSRF protection + Host validation | Done |
| Browser extension stealing form data | ❌ Awareness + subresource integrity | 🟡 |
| CSS keylogger (input[type=password]) | ✅ unsafe-inline removed from CSP | Done |
| Fetch metadata (Sec-Fetch-Dest/Site/Mode) | ❌ Validate Sec-Fetch-* headers on sensitive endpoints | 🟠 |

---

## DOMAIN 38 — LOGGING & AUDIT SECURITY

| Control | Description | Status | Priority |
|---------|-------------|--------|----------|
| Audit log immutability | Cannot update or delete audit entries | ✅ Pre-save/pre-delete hooks block | Done |
| Log injection prevention | Newlines stripped from logged values | ✅ _stripLogInjection() in logger | Done |
| Sensitive data redaction | Passwords, keys, tokens never logged | ✅ SENSITIVE_FIELDS set in logger | Done |
| Error.cause sanitization | Nested error causes sanitized | ✅ Recursive sanitize | Done |
| Mongoose error path scrub | Field paths not leaked in logs | ✅ CastError stripped | Done |
| Request body not logged | No full body logging | ✅ Only specific fields logged | Done |
| Audit log access control | Only SUPER_ADMIN can read audit logs | ❌ Audit log read API not built yet | 🟠 |
| Log shipping (SIEM) | Logs forwarded to centralized system | ❌ Datadog / Splunk | 🟠🏦 |
| Log integrity verification | Detect tampered log files | ❌ Append-only log store / WORM | 🟠🏦 |
| Log encryption in transit | TLS for log shipping | ❌ Log shipper TLS | 🟡 |
| Log retention policy | How long to keep logs | ❌ Define: 7 years for financial | 🟠🏦 |
| Legal hold | Freeze logs for litigation | ❌ Process needed | 🟠🏦 |
| Log archival | Old logs compressed + moved to cold storage | ❌ | 🟡 |
| Non-repudiation | Irrefutable proof of who did what when | ✅ Audit log with actor, IP, before/after | Done |
| Log correlation ID | Trace single request across services | ✅ requestId propagated | Done |
| Log search encryption | If logs contain PII, encrypt at rest | ❌ DB encryption covers MongoDB logs | 🟠 |

---

## DOMAIN 39 — FRAUD DETECTION & FINANCIAL CRIME

| Control | Description | Status | Priority |
|---------|-------------|--------|----------|
| Velocity limits | Max N transactions per hour | ❌ Phase 2 | 🔴 |
| Unusual hour detection | Transaction at 3am from new IP | ❌ Phase 2 | 🟠 |
| Amount pattern detection | Exactly 9999.99 (just under report limit) | ❌ Phase 2 | 🔴🏦 |
| Geographic anomaly | Login India, tx from Nigeria same minute | ✅ S-4 new IP detected | Done |
| Device fingerprinting | Same device reused across multiple accounts | ❌ Phase 2 | 🟠 |
| Behavioral biometrics | Typing speed, mouse movement patterns | ❌ Phase 3 | 🏦 |
| Money structuring detection | Breaking one large tx into many small | ❌ Phase 2 | 🔴🏦 |
| Round-tripping detection | Deposit then immediate same-amount withdrawal | ❌ Phase 2 | 🔴🏦 |
| Mule account detection | Account receives from many, withdraws to one | ❌ Phase 2 | 🟠🏦 |
| OFAC sanctions screening | Check wallet addresses against OFAC list | ❌ Phase 2 | 🔴🏦 |
| UN/EU sanctions screening | Same for EU/UN lists | ❌ Phase 2 | 🔴🏦 |
| STR (Suspicious Transaction Report) | Required report above threshold | ❌ Phase 2 | 🔴🏦 |
| KYC for merchants | Identity verification | ❌ Phase 2 | 🔴🏦 |
| Fraud score per transaction | ML-based risk scoring | ❌ Phase 3 | 🏦 |
| Block listing of bad actors | Known fraud addresses | ❌ Phase 2 | 🔴 |

---

## DOMAIN 40 — CONTAINER & ORCHESTRATION SECURITY

| Control | Status | Priority |
|---------|--------|----------|
| Non-root user in container | ❌ Dockerfile USER node | 🟠 |
| Read-only root filesystem | ❌ Dockerfile / K8s securityContext | 🟠 |
| No privileged containers | ❌ K8s securityContext.privileged:false | 🟠 |
| No host network mode | ❌ K8s hostNetwork:false | 🟠 |
| No Docker socket mount | ❌ Never mount /var/run/docker.sock | 🔴 |
| Image tag pinning (digest) | ❌ Pin to sha256 digest not :latest | 🟠 |
| Image vulnerability scanning | ❌ Trivy / Snyk Container | 🟠 |
| Container image signing | ❌ cosign / Sigstore | 🟡 |
| Runtime security (Falco) | ❌ Detect anomalous syscalls | 🟠🏦 |
| K8s network policies | ❌ Deny all, allow only needed | 🔴 |
| K8s RBAC (service accounts) | ❌ Least privilege service accounts | 🟠 |
| K8s secrets vs Vault | ❌ Use Vault not K8s secrets (base64 encoded = no encryption) | 🔴 |
| K8s etcd encryption | ❌ Encrypt etcd at rest | 🟠🏦 |
| K8s API server not public | ❌ Private cluster | 🔴 |
| Pod security admission | ❌ Enforce securityContext rules | 🟠 |
| Sidecar injection security | ❌ Verify sidecar images | 🟡 |
| Registry authentication | ❌ Pull from private registry only | 🟠 |

---

## DOMAIN 41 — THREAT MODELING (STRIDE + MITRE ATT&CK)

### STRIDE Analysis

| Threat | Category | Example | Mitigation | Status |
|--------|----------|---------|-----------|--------|
| Spoofing | Authentication | Fake merchant JWT | ✅ HS256 algorithm pinned | Done |
| Spoofing | Authentication | Impersonate admin via role | ✅ DB role always fresh | Done |
| Tampering | Integrity | Modify invoice amount in transit | ✅ HTTPS + HMAC signatures | Done |
| Tampering | Integrity | Alter balance directly in DB | ✅ Atomic ops + audit log | Done |
| Repudiation | Non-repudiation | Deny making a withdrawal | ✅ Audit log with actor | Done |
| Info Disclosure | Confidentiality | Leak private key via error | ✅ Keys zeroed + not logged | Done |
| Info Disclosure | Confidentiality | MongoDB auth data via injection | ✅ NoSQL sanitized | Done |
| DoS | Availability | Flood auth endpoint | ✅ Rate limiting per endpoint | Done |
| DoS | Availability | Blockchain listener block | ❌ Circuit breaker Phase 2 | 🟠 |
| EoP | Authorization | MERCHANT escalates to ADMIN | ✅ RBAC + DB role | Done |
| EoP | Authorization | ADMIN escalates to SUPER_ADMIN | ✅ canModifyUser() | Done |

### Key MITRE ATT&CK Techniques (Crypto Payment Context)

| Technique ID | Description | Mitigation | Status |
|-------------|-------------|-----------|--------|
| T1078 | Valid Account abuse (stolen creds) | ✅ 2FA + anomaly detection | Done |
| T1110 | Brute force authentication | ✅ Account lockout + rate limit | Done |
| T1552 | Credentials in environment | ✅ Deleted from process.env | Done |
| T1040 | Network sniffing | ✅ TLS enforced | Done |
| T1557 | MITM / AiTM | ✅ HSTS + cert pinning planned | ⚠️ |
| T1190 | Exploit public-facing app | ✅ Input validation + WAF needed | ⚠️ |
| T1059 | Command execution (injection) | ✅ No shell exec in app | Done |
| T1083 | File/directory discovery | ✅ Safe paths + no directory listing | Done |
| T1530 | Data from cloud storage | ❌ Encrypt S3/cloud storage | 🟠 |
| T1485 | Data destruction (DB wipe) | ❌ Backup + immutable audit | 🟠 |
| T1486 | Ransomware | ❌ Offline backups | 🟠🏦 |

---

## DOMAIN 42 — OPERATIONAL SECURITY & VENDOR RISK

| Control | Description | Status | Priority |
|---------|-------------|--------|----------|
| Security patch management | OS/npm updates within 7 days of CVE | ❌ Process needed | 🔴 |
| Change management | All prod changes documented | ❌ Process needed | 🟠 |
| Principle of least surprise | Code behaves predictably | ✅ Fail-safe defaults everywhere | Done |
| Third-party security assessment | Assess every vendor / library | ❌ Process needed | 🟠 |
| Vendor access revocation | Remove vendor access when contract ends | ❌ Process needed | 🟠 |
| Four-eyes principle | Two people required for sensitive ops | ❌ Multi-sig for withdrawals | 🔴🏦 |
| Security awareness training | All developers trained annually | ❌ Process needed | 🟠 |
| Secure code review | All PRs reviewed for security | ❌ Process needed | 🟠 |
| Penetration testing schedule | Annual external pentest | ❌ CREST-certified tester | 🟠🏦 |
| Vulnerability disclosure policy | security.txt + responsible disclosure | ❌ Create security.txt | 🟡 |
| Bug bounty program | HackerOne / Bugcrowd | ❌ Phase 3 | 🟡 |
| Emergency response plan | Who does what when breach happens | ❌ Document needed | 🔴 |
| Communication plan | Who to notify (regulators, customers) | ❌ Document needed | 🔴🏦 |
| TronGrid dependency risk | If TronGrid down, no blockchain data | ❌ Fallback RPC endpoint | 🟠 |
| npm registry dependency risk | npmjs.com outage | ❌ Private npm mirror for critical pkgs | 🟡 |
| Developer laptop policy | Encrypt, lock screen, no local DB dumps | ❌ MDM policy | 🟠 |
