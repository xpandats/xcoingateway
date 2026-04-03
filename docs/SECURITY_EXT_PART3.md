# XCoinGateway — Extended Security Reference — Part 3 of 3
## Domains 43–53 | INTERNAL CONFIDENTIAL

---

## DOMAIN 43 — API DESIGN SECURITY (DEEP)

| Attack | Description | Status | Priority |
|--------|-------------|--------|----------|
| API key in URL | `GET /api?apiKey=abc` — logged by CDN/proxy | ✅ API key in X-Api-Key header only | Done |
| Swagger/OpenAPI in production | Route discovery for attackers | ❌ Remove or auth-gate swagger in prod | 🟠 |
| Excessive data exposure | API returns full object; client filters | ⚠️ toSafeJSON() on user; not all models | 🟠 |
| Lack of resource ownership validation | GET /invoice/:id without merchant filter | ✅ ownershipFilter on all queries | Done |
| Mass assignment via JSON | Extra fields accepted by API | ✅ Joi stripUnknown + Mongoose strict:true | Done |
| Unsafe HTTP methods | DELETE /api/v1/all-wallets | ✅ No dangerous routes exist | Done |
| API deprecation without sunset | Old /v0/ route still active | ❌ Remove or auth-gate old versions | 🟠 |
| Broken object level auth between versions | v1 secured, v0 not | ❌ Audit all versions | 🟠 |
| Function level RBAC bypass | Admin-only endpoint accessible to merchant | ✅ requirePermission on every admin route | Done |
| Unrestricted resource consumption | No DB query cost limit | ✅ Query timeout 10s + pagination | Done |
| Bulk request flooding | POST 1000 times/second | ✅ Rate limiting per IP | Done |
| GraphQL introspection | Exposes all types and fields | ✅ No GraphQL used | Done |
| HTTP verb tampering | PUT where POST expected | ✅ Routes only accept specific methods | Done |
| API response consistency | Some errors leak field names | ❌ Standardize ALL error responses | 🟠 |
| Empty body accepted | Route that requires body accepts empty {} | ✅ Joi validates required fields | Done |
| Null values in required fields | `{"email": null}` bypasses required | ✅ Joi rejects null for required | Done |
| Array instead of object | `[{"email":"x"}]` when object expected | ✅ Joi object schema rejects arrays | Done |
| Extra large page size | limit=999999 for pagination | ✅ max limit=100 enforced | Done |
| Negative page/limit | page=-1 causes unexpected behavior | ✅ Joi min(1) on both | Done |
| Sort by sensitive field | sortBy=passwordHash | ✅ sortBy whitelist: createdAt,amount,status | Done |

---

## DOMAIN 44 — PRIVACY & DATA PROTECTION

| Control | Description | Status | Priority |
|---------|-------------|--------|----------|
| PII minimization | Collect only what's needed | ⚠️ Email, name collected; review other fields | 🟠 |
| PII encryption at field level | Email, name encrypted in DB | ❌ Plaintext in MongoDB | 🟠🏦 |
| Data anonymization | Logs don't contain PII | ⚠️ userId logged, not email; but userId is linkable | 🟡 |
| IP address anonymization | IPs hashed before storing | ✅ lastLoginIp is SHA-256 truncated | Done |
| Right to erasure (GDPR Art.17) | User can delete their account + data | ❌ Not implemented | 🟠 |
| Right to portability (GDPR Art.20) | Data export in machine-readable format | ❌ Not implemented | 🟡 |
| Privacy by design (GDPR Art.25) | Default settings most privacy-protective | ⚠️ Partial | 🟠 |
| Data retention limits | Auto-delete old data per policy | ❌ No TTL policies set | 🟠 |
| Third-party data sharing | No sharing without explicit consent | ✅ No third-party integrations | Done |
| Privacy policy technical compliance | Policy matches actual data use | ❌ Legal document needed | 🟠 |
| Consent management | Record user consent with timestamp | ❌ Not built | 🟡 |
| Cookie consent | For any analytics cookies | ✅ No tracking cookies used | Done |
| Data breach notification (72hr) | GDPR Art.33 | ❌ Process needed | 🔴🏦 |
| Data processing register | Record of all processing activities | ❌ Legal document needed | 🟠🏦 |
| Sub-processor agreements | DPAs with MongoDB Atlas, cloud providers | ❌ | 🟠🏦 |

---

## DOMAIN 45 — SUPPLY CHAIN & DEPENDENCY SECURITY (DEEP)

| Attack | Description | Status | Priority |
|--------|-------------|--------|----------|
| Malicious npm package | bgd (vs bcrypt) installed by typo | ⚠️ npm audit; need Dependabot + scoped registry | 🟠 |
| Dependency confusion | Private package `@xcg/crypto` fetched from npmjs | ❌ npm scope configuration + private registry | 🟠 |
| Lockfile tampering | package-lock.json modified in PR | ❌ CI: verify lockfile integrity | 🟠 |
| Transitive dependency vulnerability | Direct dep is fine; its dep has CVE | ⚠️ npm audit covers some | 🟠 |
| npm postinstall scripts | A package runs code on npm install | ❌ `--ignore-scripts` in production CI | 🟠 |
| Build-time secret injection | Secret in docker build arg | ❌ Never use build args for secrets | 🟠 |
| CI/CD secret exposure | GitHub Actions logs expose secrets | ❌ Mask secrets in all CI outputs | 🟠 |
| Git history secret scan | Old commit has plaintext key | ❌ Pre-commit hook + GitGuardian | 🔴 |
| Compromised npm account | Maintainer account hacked; malicious version | ⚠️ 2FA on npm account | 🟠 |
| SBOM (Software Bill of Materials) | List all dependencies for audit | ❌ Syft / CycloneDX | 🟡 |
| GitHub Actions from untrusted repo | `uses: someuser/action@main` | ❌ Pin all actions to commit SHA | 🟠 |
| Docker base image compromise | `FROM node:20` has vulns | ❌ Use distroless/Pin specific digest | 🟠 |
| npm registry mirror | Use private mirror for reproducible builds | ❌ JFrog Artifactory / Verdaccio | 🟡 |
| Open source license violations | GPL code in commercial product | ❌ FOSSA / license scanner | 🟡 |

---

## DOMAIN 46 — SECRETS MANAGEMENT (DEEP)

| Control | Description | Status | Priority |
|---------|-------------|--------|----------|
| Secrets in .env files | Risk if file leaked | ✅ .gitignore; .env not committed | Done |
| .env file permissions | World-readable on server | ❌ chmod 600 .env.* | 🟠 |
| Secrets in process.env | Available to all code after startup | ✅ Deleted from process.env after SC-3 | Done |
| Secrets in error messages | `MASTER_KEY=abc123 in config error` | ✅ Config errors don't echo values | Done |
| Secrets in logs | `masterKey: "abc..."` in debug log | ✅ SENSITIVE_FIELDS set redacts them | Done |
| Secrets in metrics/telemetry | APM agent captures env variables | ❌ Configure APM to exclude sensitive vars | 🟠 |
| Secrets in heap dump | Memory snapshot contains key bytes | ⚠️ Buffer zeroed; HSM eliminates fully | 🟠🏦 |
| Secret rotation mechanism | No way to rotate without downtime | ❌ Vault dynamic secrets / key versioning | 🟠🏦 |
| JWT secret rotation | Old JWTs still valid during rotation | ❌ Key ID (kid) claim + JWKS endpoint | 🟠 |
| Master key rotation | Re-encrypt all wallet keys with new master | ❌ No rotation mechanism | 🔴🏦 |
| API key rotation | Merchant rotates without service interruption | ⚠️ Revoke+create flow; no overlap period | 🟠 |
| Vault integration | HashiCorp Vault for dynamic secrets | ❌ Phase 2 | 🔴🏦 |
| AWS Secrets Manager | Alternative to Vault | ❌ Phase 2 | 🔴🏦 |
| Secret access audit | Log every secret access | ❌ Vault provides this automatically | 🟠🏦 |
| Short-lived credentials | DB passwords rotate every 24h | ❌ Vault dynamic secrets | 🏦 |

---

## DOMAIN 47 — NTP & TIME-BASED ATTACKS

| Attack | Description | Status | Priority |
|--------|-------------|--------|----------|
| NTP spoofing | Attacker shifts server time → token replay | ❌ Use NTP pool with auth + monitoring | 🟠 |
| TOTP window manipulation | Attacker shifts time server to replay TOTP | ✅ window=0 narrows attack window | Done |
| Replay via timestamp manipulation | Old signed request replayed if time shifted | ✅ timestamp validated within 5min window | Done |
| JWT iat in future | Token with iat > now (time skew) | ❌ Validate iat not in future | 🟡 |
| Expired invoice extended | System clock drift makes expired invoice valid | ❌ Use UTC consistently, NTP sync | 🟡 |
| Cron job drift | Cleanup jobs miss expired records | ❌ Monitor cron execution + NTP | 🟡 |
| Distributed clock skew | Services disagree on time | ❌ Sync all services to same NTP pool | 🟠 |
| Blockchain timestamp manipulation | Block timestamp ≠ real time | ❌ Use block height not timestamp for expiry | 🟠 |

---

## DOMAIN 48 — NETWORK PROTOCOL SECURITY (DEEP)

| Protocol/Attack | Status | Priority |
|----------------|--------|----------|
| DNS cache poisoning — outbound resolvers | ❌ DNSSEC-validating resolver | 🟠 |
| DNS rebinding — webhook validation | ✅ ssrfProtection.js resolves + checks | Done |
| DNS TTL manipulation | ❌ Pin critical hostnames in /etc/hosts | 🟡 |
| BGP hijacking (path to our server) | ❌ Cloud provider + prefix filtering | 🏦 |
| ARP spoofing (internal network) | ❌ Network switch security / VLAN | 🏦 |
| ICMP redirect injection | ❌ Disable ICMP redirects on servers | 🟡 |
| TCP RST injection | ❌ TLS prevents meaningful attack | Done |
| UDP source port randomization | ❌ OS-level (modern kernels do this) | Done |
| IPv6 tunneling exfiltration | ❌ Block unused IPv6 at firewall | 🟡 |
| QUIC protocol attacks (HTTP/3) | ❌ Not using HTTP/3 yet | 🟡 |
| gRPC header injection | ❌ Not using gRPC yet | 🟡 |

---

## DOMAIN 49 — RUNTIME APPLICATION SELF-PROTECTION (RASP)

| Control | Description | Status | Priority |
|---------|-------------|--------|----------|
| Attack detection in middleware chain | Block known patterns before business logic | ✅ Multiple security middlewares | Done |
| Request context anomaly detection | Suspicious IP+UA combination | ✅ S-3, S-4 implemented | Done |
| Real-time HMAC tampering detection | Modified request body | ✅ Signature validation | Done |
| Real-time injection detection | $ keys / prototype keys blocked | ✅ noSqlSanitize | Done |
| Real-time rate limit enforcement | Per-IP per-endpoint | ✅ Rate limiting middlewares | Done |
| Automatic account lockout | After N failed attempts | ✅ lockUntil in User model | Done |
| Self-test on startup (config) | Validate all secrets before accepting traffic | ✅ validateConfig() + validateMasterKey() | Done |
| Graceful degradation | If Redis down, fallback rate limiter | ✅ In-memory fallback | Done |
| Process watchdog | Restart if memory exceeds limit | ✅ PM2 max_memory_restart:512M | Done |
| Heap monitoring | Alert if heap > 90% | ❌ Custom metrics + alerting | 🟠 |
| Full RASP tool (Sqreen/Contrast) | Agent-based runtime protection | ❌ Phase 2 consideration | 🟡 |

---

## DOMAIN 50 — SECURITY TESTING METHODOLOGY

| Test Type | Tool/Method | Status | Priority |
|-----------|------------|--------|----------|
| Static Analysis (SAST) | Semgrep / ESLint security rules | ❌ | 🟠 |
| Dynamic Analysis (DAST) | OWASP ZAP / Burp Suite | ❌ | 🟠 |
| Dependency scanning | npm audit + Snyk | ⚠️ npm audit in scripts | 🟠 |
| Secret scanning | GitGuardian / truffleHog | ❌ | 🔴 |
| Container scanning | Trivy / Snyk Container | ❌ | 🟠 |
| Fuzzing | Jest property-based / fast-check | ❌ | 🟡 |
| Unit tests for auth | Login, token, RBAC test cases | ⚠️ security.test.js exists (check status) | 🟠 |
| Integration tests end-to-end | Full payment flow test | ❌ | 🟠 |
| Load testing | k6 / Artillery to find DoS limits | ❌ | 🟠 |
| Chaos engineering | Kill Redis, kill DB, network partition | ❌ | 🟡 |
| Red team exercise | External team attacks production-clone | ❌ | 🏦 |
| Purple team | Red + Blue cooperate to improve | ❌ | 🏦 |
| Penetration test (CREST) | Annual certified external test | ❌ | 🏦 |
| Bug bounty | Public program (HackerOne) | ❌ | 🟡 |
| Threat model review | Quarterly STRIDE review | ❌ | 🟠 |

---

## DOMAIN 51 — SIGNING SERVICE ARCHITECTURE (PHASE 2)

| Requirement | Description | Status | Priority |
|-------------|-------------|--------|----------|
| Separate process for signing | HTTP server cannot call signing directly | ❌ Phase 2 | 🔴🏦 |
| Queue-only interface (no HTTP) | Signing listens on Redis queue only | ❌ Phase 2 | 🔴🏦 |
| Separate OS user | Signing service runs as `xcg-signer` user | ❌ Phase 2 | 🔴🏦 |
| Private keys never leave signing process | No return of decrypted key to caller | ❌ Phase 2 | 🔴🏦 |
| Key zeroed after signing | Buffer.fill(0) immediately after use | ✅ Code supports Buffer; signing not built yet | ⚠️ |
| Request/response encryption | Queue messages encrypted (not just signed) | ❌ Phase 2 | 🔴🏦 |
| Signing queue authentication | Only withdrawal engine can submit | ❌ Redis ACL or signed queue messages | 🔴🏦 |
| Signing audit log | Every signing request logged with txn ID | ❌ Phase 2 | 🔴🏦 |
| Rate limit on signing | Max N signatures per minute | ❌ Phase 2 | 🔴🏦 |
| Multi-signature for large amounts | 2-of-3 keys required above threshold | ❌ Phase 3 | 🏦 |
| HSM-backed signing | Keys in CloudHSM / Vault Transit | ❌ Phase 3 | 🔴🏦 |
| Signing request approval (2-person) | Two admins approve large withdrawals | ❌ Phase 3 | 🏦 |

---

## DOMAIN 52 — REGULATORY & LEGAL LANDSCAPE

| Regulation | Region | Requirement | Status | Priority |
|-----------|--------|-------------|--------|----------|
| GDPR | EU | Data protection, right to erasure, 72hr breach notification | ❌ Partial | 🔴🏦 |
| CCPA | California | Opt-out of data sale, access rights | ❌ | 🟡🏦 |
| MiCA | EU | Crypto asset service provider license | ❌ | 🔴🏦 |
| VASP registration | Most countries | Register as Virtual Asset Service Provider | ❌ | 🔴🏦 |
| Money transmission license | US states | Required in most US states | ❌ | 🔴🏦 |
| AML/CFT compliance | Global | Anti-money laundering controls | ❌ | 🔴🏦 |
| FATF Travel Rule | Global | Share originator/beneficiary info on transfers >$1000 | ❌ | 🔴🏦 |
| OFAC compliance | US | Screen against sanctioned entities/addresses | ❌ | 🔴🏦 |
| UN/EU sanctions | Global | Separate sanctions lists | ❌ | 🔴🏦 |
| KYC for merchants | Global | Verify merchant identity before activation | ❌ | 🔴🏦 |
| KYC for end users | Some jurisdictions | End-user identity verification | ❌ | 🟠🏦 |
| STR (Suspicious Transaction Report) | Most | File reports on suspicious activity | ❌ | 🔴🏦 |
| PCI-DSS | If card-adjacent | Data security standard | ❌ | 🏦 |
| SOC 2 Type II | Enterprise customers | 6-month audit + report | ❌ | 🏦 |
| ISO 27001 | Enterprise | Annual ISMS audit | ❌ | 🏦 |
| Data localization | India/China/Russia | Store data within jurisdiction | ❌ | 🟡🏦 |
| Audit trail legal hold | Financial regulations | 5-7 year retention | ❌ | 🟠🏦 |

---

## DOMAIN 53 — COMPLETE XCG SECURITY POSTURE SCORE

```
╔══════════════════════════════════════════════════════════════════╗
║           XCOINGATEWAY SECURITY POSTURE — HONEST SCORE          ║
╠══════════════════════════════════════════════════════════════════╣
║ DOMAIN                        IMPLEMENTED  PARTIAL  MISSING      ║
║ ─────────────────────────────────────────────────────────────── ║
║ 01 Network & Transport              35%      15%      50%        ║
║ 02 Authentication                   80%      10%      10%        ║
║ 03 Session & Token                  85%       5%      10%        ║
║ 04 Authorization                    82%       8%      10%        ║
║ 05 Injection (All Types)            85%       5%      10%        ║
║ 06 XSS                              55%       5%      40%        ║
║ 07 CSRF & UI                        90%       5%       5%        ║
║ 08 API Security                     80%      10%      10%        ║
║ 09 Database Security                55%       5%      40%        ║
║ 10 Cryptography                     72%       8%      20%        ║
║ 11 Memory & Process                 60%      10%      30%        ║
║ 12 Infrastructure                   10%       5%      85%        ║
║ 13 Supply Chain                     35%      15%      50%        ║
║ 14 Frontend                          3%       2%      95%        ║
║ 15 Blockchain / Crypto              45%       5%      50%        ║
║ 16 Physical & Hardware               0%       0%     100%        ║
║ 17 IAM & PAM                        20%       5%      75%        ║
║ 18 Monitoring & Detection           55%       5%      40%        ║
║ 19 Compliance                        2%       3%      95%        ║
║ 20 Social Engineering                5%       5%      90%        ║
║ 21 Business Continuity               8%       2%      90%        ║
║ 22 Quantum Computing                10%       0%      90%        ║
║ 23 Timing Attacks                   75%       5%      20%        ║
║ 24 Race Conditions                  50%      10%      40%        ║
║ 25 Serialization                    88%       7%       5%        ║
║ 26 Encoding / Unicode               70%       0%      30%        ║
║ 27 HTTP Protocol                    55%      10%      35%        ║
║ 28 Cache Security                    5%       5%      90%        ║
║ 29 Access Control Bypass            85%       5%      10%        ║
║ 30 Configuration                    75%       5%      20%        ║
║ 31 Error & Info Disclosure          80%       5%      15%        ║
║ 32 Crypto Protocol Attacks          80%       5%      15%        ║
║ 33 Financial / Payment              35%       0%      65%        ║
║ 34 Email Security                    0%       0%     100%        ║
║ 35 WebSocket Security                0%       0%     100%        ║
║ 36 Multi-Tenancy                    80%       5%      15%        ║
║ 37 Browser Security                 45%       5%      50%        ║
║ 38 Logging & Audit                  75%      10%      15%        ║
║ 39 Fraud Detection                   5%       5%      90%        ║
║ 40 Container & Orchestration         0%       0%     100%        ║
║ 41 Threat Modeling                  60%      10%      30%        ║
║ 42 Operational Security             10%       5%      85%        ║
║ 43 API Design (deep)                80%      10%      10%        ║
║ 44 Privacy & Data Protection        20%      10%      70%        ║
║ 45 Supply Chain (deep)              20%      15%      65%        ║
║ 46 Secrets Management               55%      10%      35%        ║
║ 47 NTP & Time Attacks               45%       5%      50%        ║
║ 48 Network Protocol                 50%       5%      45%        ║
║ 49 Runtime Self-Protection          75%       5%      20%        ║
║ 50 Security Testing                 10%      10%      80%        ║
║ 51 Signing Service                  10%       5%      85%        ║
║ 52 Regulatory & Legal                0%       5%      95%        ║
║ ─────────────────────────────────────────────────────────────── ║
║ CODE-LEVEL SECURITY:                 ~72% complete               ║
║ INFRASTRUCTURE SECURITY:             ~12% complete               ║
║ FINANCIAL BUSINESS LOGIC:            ~35% complete               ║
║ COMPLIANCE & REGULATORY:             ~03% complete               ║
║ OVERALL FOR BANK-GRADE:              ~25% complete               ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## PRIORITY ACTION MATRIX (Next 90 Days)

### 🔴 MUST DO BEFORE FIRST REAL TRANSACTION
1. Minimum blockchain confirmations (19+ Tron)
2. Fake USDT contract address validation (whitelist)
3. Withdrawal cooling-off + daily limits
4. Signing service process isolation
5. Redis auth + private network only
6. Distributed race condition lock (withdrawal)
7. Secret scanning in CI (GitGuardian)
8. Block 0-confirmation crediting
9. Emergency incident response plan

### 🟠 MUST DO WITHIN 30 DAYS OF LAUNCH
1. Cloudflare WAF + DDoS protection
2. HashiCorp Vault for secrets
3. MongoDB Atlas: encryption at rest + VPC peering
4. mTLS between internal services
5. Separate DB users per service
6. Mandatory 2FA for all merchants
7. KYC for merchant activation
8. OFAC/sanctions screening on wallets
9. Cache-Control: no-store on all API responses
10. HTTP/2 rapid reset mitigation (Nginx config)

### 🟡 WITHIN 90 DAYS
1. Unicode/homoglyph normalization
2. Host header validation
3. JWT secret rotation mechanism (kid claim)
4. Email security (SPF/DKIM/DMARC)
5. SIEM integration (Datadog)
6. Behavioral anomaly detection for fraud
7. JSON depth limit middleware
8. Pen test by external CREST-certified firm
9. Vulnerability disclosure policy (security.txt)

### 🏦 WITHIN 6 MONTHS (Bank-Grade)
1. HSM for master encryption key (AWS CloudHSM)
2. Multi-signature for withdrawals above threshold
3. Cold storage for 90%+ of reserves
4. SOC 2 Type II audit initiation
5. Full AML/KYC compliance
6. FATF Travel Rule implementation
7. GDPR compliance (right to erasure, 72hr notification)
8. Bug bounty program (HackerOne)
9. Post-quantum algorithm agility design
10. Annual penetration test schedule

---

*Documents: SECURITY_COMPLETE_REFERENCE.md (Domains 1-22) + SECURITY_EXT_PART1.md (23-32) + SECURITY_EXT_PART2.md (33-42) + SECURITY_EXT_PART3.md (43-53)*
*Total: 53 Domains | 600+ Controls | Zero Tolerance Target*
*XCoinGateway Security Team | 2026-04-03*
