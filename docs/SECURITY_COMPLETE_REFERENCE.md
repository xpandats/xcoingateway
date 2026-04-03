# XCoinGateway — Complete Bank-Grade Security Reference
## Classification: INTERNAL | CONFIDENTIAL
### Version 1.0 | 2026-04-03

---

## HOW TO READ THIS DOCUMENT

| Symbol | Meaning |
|--------|---------|
| ✅ | Implemented in codebase |
| ⚠️ | Partially implemented |
| ❌ | Not yet implemented |
| 🏗️ | Phase 2 work item |
| 🔴 | Critical — must fix before live money |
| 🟠 | High — fix before scale |
| 🟡 | Medium — fix within 90 days |
| 🟢 | Low — fix within 1 year |
| 🏦 | Required for true bank-grade |

---

## DOMAIN 1 — NETWORK & TRANSPORT LAYER

### 1.1 DDoS & Volumetric Attacks
| Attack | Risk | Status | Priority |
|--------|------|--------|----------|
| HTTP flood (L7) | App crash | ✅ Rate limiting (Redis-backed) | Done |
| SYN flood (L4) | TCP exhaustion | ❌ Needs Cloudflare/AWS Shield | 🔴 |
| UDP amplification | Bandwidth exhaustion | ❌ Cloud infra layer | 🟠 |
| ICMP flood | Network saturation | ❌ Cloud infra layer | 🟠 |
| Slowloris (slow headers) | Thread exhaustion | ✅ server.timeout=30s | Done |
| HTTP/2 rapid reset | DoS via stream resets | ❌ Nginx config needed | 🔴 |
| ReDoS EventLoop block | Node.js frozen | ✅ Regex rewritten (4 separate tests) | Done |
| Memory exhaustion via body | Heap OOM | ✅ Body size limits (10kb/100kb) | Done |
| CPU exhaustion via bcrypt | Thread starvation | ✅ Rate limit on auth endpoints | Done |

### 1.2 Man-in-the-Middle (MITM)
| Attack | Risk | Status | Priority |
|--------|------|--------|----------|
| SSL stripping | Plaintext exposure | ✅ HSTS preload + HTTPS redirect | Done |
| Certificate spoofing | Impersonation | ✅ Expect-CT + HSTS | Done |
| BGP route hijacking | Traffic misdirection | ❌ Cloud provider + Cloudflare | 🏦 |
| DNS cache poisoning | Redirect to attacker | ❌ DNSSEC needed | 🟠 |
| ARP poisoning (internal) | Internal MITM | ❌ Network segmentation + mTLS | 🔴 |
| Wi-Fi intercept | Data in transit | ✅ TLS enforced | Done |
| Certificate authority compromise | Fraudulent cert | ✅ Certificate Transparency + CAA | Done |
| HTTPS downgrade (BEAST) | Cipher weakness | ❌ TLS 1.3 only not enforced (Nginx) | 🟠 |
| HSTS bypass (new subdomain) | Session hijack | ⚠️ HSTS set, preload list submission needed | 🟡 |

### 1.3 TLS / PKI Security
| Item | Status | Priority |
|------|--------|----------|
| TLS 1.3 only (disable 1.0/1.1/1.2) | ❌ Nginx config | 🟠 |
| Perfect Forward Secrecy (ECDHE) | ❌ Nginx cipher config | 🟠 |
| OCSP Stapling | ❌ Nginx config | 🟡 |
| Certificate pinning (TronGrid API) | ❌ Phase 2 | 🟠 |
| mTLS internal services | ❌ Service mesh needed | 🔴 |
| CAA DNS record (limit who can issue cert) | ❌ DNS config | 🟡 |
| 2048+ bit RSA / P-256 ECDSA | ✅ Used implicitly by Let's Encrypt | Done |
| Certificate auto-renewal | ❌ Let's Encrypt + Certbot | 🟠 |
| Private key for TLS in HSM | ❌ Software key now | 🏦 |

### 1.4 Network Architecture
| Item | Status | Priority |
|------|--------|----------|
| Zone 1: Public (API Gateway only) | ❌ Not deployed | 🔴 |
| Zone 2: Application (internal only) | ❌ Not deployed | 🔴 |
| Zone 3: Vault (no HTTP, queue-only) | ❌ Not deployed | 🔴 |
| Zone 4: Data (no external access) | ❌ Not deployed | 🔴 |
| WAF (Cloudflare / Nginx+ModSecurity) | ❌ Not deployed | 🔴 |
| Firewall rules (allowlist per port) | ❌ Not deployed | 🔴 |
| Port scanning defense | ❌ Cloud security groups | 🟠 |
| IP reputation blocking | ❌ Cloudflare / Fail2ban | 🟠 |
| Geo-blocking (high-risk regions) | ❌ Cloudflare rules | 🟡 |

---

## DOMAIN 2 — AUTHENTICATION & IDENTITY

### 2.1 Password Security
| Attack / Control | Risk | Status | Priority |
|-----------------|------|--------|----------|
| Brute force | Account takeover | ✅ Lockout after 5 fails | Done |
| Credential stuffing | Mass account takeover | ✅ Rate limit by IP | Done |
| Password reuse | Lateral movement | ✅ Password history (last 5) | Done |
| Weak password | Easy guess | ✅ Complexity + min 8 chars | Done |
| bcrypt timing attack | Account enumeration | ✅ Always hash, same timing | Done |
| Rainbow table | Hash reversal | ✅ bcrypt + high salt rounds | Done |
| Password spray (1 password × many users) | Bypass lockout | ⚠️ Need per-IP cross-account detection | 🟠 |
| Argon2 vs bcrypt | Memory-hard is stronger | ❌ Still using bcrypt | 🟡 |
| Compromised password DB check | Known breach | ❌ HaveIBeenPwned API check | 🟡 |

### 2.2 Multi-Factor Authentication
| Control | Status | Priority |
|---------|--------|----------|
| TOTP (6-digit, 30s window) | ✅ Implemented (window=0) | Done |
| TOTP replay prevention (used codes) | ✅ UsedTotpCode collection | Done |
| 2FA enforcement (mandatory) | ❌ Currently optional | 🔴 |
| Hardware token (FIDO2/WebAuthn) | ❌ Phase 3 | 🏦 |
| SMS OTP (insecure — SIM swap) | ❌ Intentionally not implemented | Done |
| Email OTP | ❌ Phase 2 (backup for 2FA) | 🟡 |
| Recovery codes (one-time backup) | ❌ Phase 2 | 🟠 |
| 2FA brute force protection | ✅ Auth rate limiting | Done |
| Authenticator app binding | ✅ Secret encrypted in DB | Done |

### 2.3 Account Lifecycle
| Control | Status | Priority |
|---------|--------|----------|
| Registration requires admin approval | ✅ isApproved=false | Done |
| Account deactivation (soft disable) | ✅ isActive flag | Done |
| Account enumeration prevention | ✅ Same response + always bcrypt | Done |
| Admin role protection (SUPER_ADMIN) | ✅ canModifyUser() guard | Done |
| Role escalation prevention | ✅ DB role always fresh | Done |
| Privileged account monitoring | ❌ SIEM alerting | 🟠 |

---

## DOMAIN 3 — SESSION & TOKEN SECURITY

### 3.1 JWT Security
| Attack | Status | Priority |
|--------|--------|----------|
| Algorithm confusion (none/RS256) | ✅ algorithms:['HS256'] pinned | Done |
| Weak secret | ✅ 256-bit entropy enforced | Done |
| Token theft — no IP binding | ✅ IP prefix hash (iph) in JWT | Done |
| Stolen token from different network | ✅ authenticate.js warns on iph mismatch | Done |
| Stale role in JWT | ✅ DB role fetched on every request | Done |
| Token not revokable | ⚠️ jti added; no revocation list yet | 🟠 |
| JWT replay after password change | ✅ passwordChangedAt check | Done |
| Long-lived access token | ✅ 15min expiry | Done |
| JWT secret in version control | ✅ .env never committed | Done |
| JWT secret rotatable | ❌ No rotation mechanism | 🟠 |
| Access token interception via log | ✅ Tokens never logged | Done |

### 3.2 Refresh Token Security
| Attack | Status | Priority |
|--------|--------|----------|
| Refresh token reuse (stolen) | ✅ Family revocation on reuse | Done |
| Timing oracle (found vs revoked) | ✅ Constant-time path | Done |
| Token theft from cookie | ✅ httpOnly + SameSite:strict | Done |
| Cookie not secure in HTTP | ✅ always secure:true | Done |
| Session fixation | ✅ Family-based per-auth | Done |
| Concurrent session limit | ✅ MAX_SESSIONS_PER_USER | Done |
| Refresh from different IP/UA | ✅ Anomaly logged to audit | Done |
| Token expiry enforcement | ✅ expiresAt checked | Done |
| Token DB compromise | ✅ Hashed with SHA-256 (not raw) | Done |
| clearCookie path mismatch | ✅ Both paths cleared | Done |

### 3.3 Cookie Security
| Control | Status | Priority |
|---------|--------|----------|
| httpOnly | ✅ | Done |
| Secure (HTTPS only) | ✅ Always on | Done |
| SameSite: Strict | ✅ | Done |
| Path restriction (/api/v1/auth/refresh) | ✅ | Done |
| Cookie prefixing (__Host- / __Secure-) | ❌ Phase 2 | 🟡 |
| Cookie encryption (at cookie layer) | ❌ Token hashed in DB | 🟡 |

---

## DOMAIN 4 — AUTHORIZATION & ACCESS CONTROL

### 4.1 RBAC
| Control | Status | Priority |
|---------|--------|----------|
| Role hierarchy (MERCHANT/ADMIN/SUPER_ADMIN) | ✅ | Done |
| Permission matrix (resource:action) | ✅ rbac.js | Done |
| SUPER_ADMIN modification protection | ✅ canModifyUser() | Done |
| Ownership enforcement (merchantId filter) | ✅ ownership.js | Done |
| Stale role prevention | ✅ DB fetch on each request | Done |
| Admin panel IP whitelist | ✅ adminIpWhitelist.js | Done |
| ABAC (attribute-based) | ❌ Future scale | 🟡 |

### 4.2 Object-Level Authorization
| Attack | Status | Priority |
|--------|--------|----------|
| IDOR (access other merchant's invoice) | ✅ buildMerchantFilter enforced | Done |
| Mass assignment (extra fields to DB) | ✅ Strict Mongoose schemas | Done |
| Parameter tampering (change merchantId) | ✅ server injects merchantId | Done |
| Horizontal privilege escalation | ✅ ownership.js | Done |
| Vertical privilege escalation | ✅ RBAC + DB role | Done |
| Over-permissive API responses | ⚠️ toSafeJSON() on user, others need audit | 🟠 |

---

## DOMAIN 5 — INJECTION ATTACKS (ALL TYPES)

| Attack Type | Vector | Status | Priority |
|------------|--------|--------|----------|
| NoSQL injection | req.body $gt/$ne | ✅ noSqlSanitize.js strips $ keys | Done |
| Prototype pollution | __proto__/constructor | ✅ Blocked in sanitizer | Done |
| Log injection (CRLF) | User-Agent newlines | ✅ \n\r stripped in logger | Done |
| ReDoS | Password regex | ✅ 4 separate non-backtracking tests | Done |
| Path traversal | ../etc/passwd | ✅ safeFilePath.js utility | Done |
| Null byte injection | filename\0.js | ✅ safeFilePath.js strips \0 | Done |
| SSRF (webhook URL) | Internal metadata | ✅ ssrfProtection.js + DNS check | Done |
| SSRF (TronGrid URL) | Env injection | ✅ Allowlist in config validator | Done |
| HTTP Parameter Pollution | a=1&a=2 | ✅ hpp middleware | Done |
| Server-Side Template Injection | Template engines | ✅ No template engines used | Done |
| XML External Entity (XXE) | XML parsers | ✅ No XML parsing | Done |
| LDAP Injection | Auth queries | ✅ No LDAP used | Done |
| OS Command Injection | exec(userInput) | ✅ No shell execution | Done |
| SQL Injection | SQL queries | ✅ MongoDB only, no SQL | Done |
| Header Injection | Custom headers | ⚠️ express validates, manual check needed | 🟡 |
| CSV Injection | Export features | ❌ No exports yet (Phase 2 must sanitize) | 🟠 |
| XPath Injection | XML xpath queries | ✅ Not used | Done |
| HTML Injection | User content rendered | ✅ API only, no HTML rendering | Done |
| Email Header Injection | SMTP headers | ❌ No email yet; must sanitize when added | 🟡 |
| SMTP Injection | Email content | ❌ Future Phase | 🟡 |
| Expression Language Injection | EL in templates | ✅ Not used | Done |
| Open Redirect | redirect param | ⚠️ No current redirect; must validate if added | 🟡 |

---

## DOMAIN 6 — XSS (CROSS-SITE SCRIPTING)

| Type | Vector | Status | Priority |
|------|--------|--------|----------|
| Reflected XSS | Error page output | ✅ Generic 404 (no echo) | Done |
| Stored XSS | DB content in HTML | ✅ API-only, no HTML output | Done |
| DOM XSS | Frontend JS | ❌ Frontend not built yet | 🔴 |
| Mutation XSS | mXSS in browsers | ❌ Frontend not built yet | 🔴 |
| XSS via SVG upload | File uploads | ✅ No file uploads | Done |
| XSS via PostMessage | iframe comms | ❌ Frontend responsibility | 🟠 |
| CSS Injection / CSS exfiltration | unsafe-inline | ✅ unsafe-inline removed from CSP | Done |
| CSP bypass via CDN | CDN script injection | ✅ No CDN used (self-hosted) | Done |
| Content-Type sniffing XSS | IE/old browsers | ✅ nosniff header (Helmet) | Done |
| XSS via JSON (JSONP) | JSONP endpoints | ✅ No JSONP | Done |
| Dangling markup injection | Partial attribute injection | ✅ No HTML output | Done |

---

## DOMAIN 7 — CSRF & UI ATTACKS

| Attack | Status | Priority |
|--------|--------|----------|
| CSRF via form POST | ✅ SameSite:strict cookies | Done |
| CSRF via CORS bypass | ✅ Origin validation (server-side) | Done |
| CSRF — forged JSON POST | ✅ Content-Type enforcement | Done |
| Clickjacking (iframe embedding) | ✅ frameAncestors:'none' in CSP | Done |
| UI Redressing | ✅ X-Frame-Options via Helmet | Done |
| Drag-and-drop attacks | ✅ No drag-drop UI | Done |
| Cross-origin data leakage | ✅ CORS allowlist strict | Done |
| CORS misconfiguration | ✅ Origin list from ENV, validated | Done |
| Cross-origin PostMessage | ❌ Frontend responsibility | 🟠 |

---

## DOMAIN 8 — API SECURITY

### 8.1 API Authentication
| Control | Status | Priority |
|---------|--------|----------|
| JWT (user-facing) | ✅ 15min access token | Done |
| HMAC-SHA256 (merchant API) | ✅ merchantAuth.js | Done |
| API key entropy | ✅ 64-char hex (256-bit) | Done |
| API key expiry | ✅ expiresAt on API keys | Done |
| API key rotation | ⚠️ Revoke+create flow exists, no UI | 🟠 |
| Nonce (replay prevention) | ✅ UUID nonce + Redis store | Done |
| Timestamp window (5 min) | ✅ merchantAuth.js | Done |
| HMAC signature verification | ✅ Constant-time comparison | Done |
| JSON body sort (deterministic HMAC) | ✅ Sorted before signing | Done |

### 8.2 API Design Security
| Control | Status | Priority |
|---------|--------|----------|
| Idempotency keys | ✅ Invoice.createIdempotent() | Done |
| Rate limiting per endpoint | ✅ Separate buckets | Done |
| Rate limiting per merchant | ✅ merchantRateLimit.js | Done |
| Request timeout (30s) | ✅ server.timeout | Done |
| Response size limits | ⚠️ Pagination exists, no hard cap | 🟡 |
| API versioning | ✅ /api/v1/ prefix | Done |
| Error response sanitization | ✅ AUTH_ERROR in production | Done |
| Stack trace in errors | ✅ Hidden in production | Done |
| Verbose 404 (path echo) | ✅ Generic 404 message | Done |
| GraphQL depth/complexity limit | ✅ No GraphQL used | Done |
| Mass data extraction prevention | ✅ max 100 per page | Done |

---

## DOMAIN 9 — DATABASE SECURITY

### 9.1 Query Security
| Control | Status | Priority |
|---------|--------|----------|
| Object ID validation (BSON injection) | ✅ validateObjectId() | Done |
| Schema strict mode (reject unknown fields) | ✅ strict:true all models | Done |
| Query timeout (global 10s maxTimeMS) | ✅ connection.js | Done |
| Parameterized queries (no string concat) | ✅ Mongoose ORM | Done |
| Aggregate pipeline injection | ⚠️ Manual review needed | 🟠 |
| $where operator (JS execution) | ✅ Blocked by sanitizer | Done |
| Regex injection in queries | ⚠️ Need to anchor user-supplied regex | 🟡 |

### 9.2 Data Encryption
| Control | Status | Priority |
|---------|--------|----------|
| Private keys: AES-256-GCM encrypted | ✅ keyManager.js | Done |
| Passwords: bcrypt hashed | ✅ | Done |
| Refresh tokens: SHA-256 hashed | ✅ | Done |
| API keys: SHA-256 hashed | ✅ | Done |
| Webhook secrets: AES-256-GCM | ✅ | Done |
| TOTP secrets: AES-256-GCM | ✅ | Done |
| Sensitive fields select:false | ✅ secureFieldsPlugin | Done |
| Encryption at rest (DB level) | ❌ MongoDB Atlas encryption / WiredTiger | 🔴🏦 |
| Client-Side Field Level Encryption (CSFLE) | ❌ MongoDB driver CSFLE | 🟠🏦 |
| Field-level encryption for PII | ❌ Email, names not encrypted | 🟠 |
| Password history encrypted | ⚠️ Stored as bcrypt hash (OK) | Done |
| Audit log entries encrypted | ❌ Stored plaintext in MongoDB | 🟡 |

### 9.3 Database Access Control
| Control | Status | Priority |
|---------|--------|----------|
| Separate DB user per service | ❌ One user currently | 🔴 |
| DB user least privilege (read-only for listeners) | ❌ | 🔴 |
| DB user for audit logs: insert-only | ❌ | 🟠 |
| MongoDB auth required | ✅ Config validator checks @ in URI | Done |
| MongoDB TLS required in production | ✅ Config validator checks tls=true | Done |
| DB connection via private network only | ❌ Deployment | 🔴 |
| MongoDB Atlas VPC peering | ❌ Deployment | 🔴 |
| Audit DB on separate instance | ❌ Same DB currently | 🟠🏦 |
| DB backup encryption | ❌ Deployment | 🟠 |
| Point-in-time recovery | ❌ MongoDB Atlas config | 🟠 |

### 9.4 Data Integrity
| Control | Status | Priority |
|---------|--------|----------|
| Atomic balance updates ($inc) | ✅ Wallet.incrementBalance() | Done |
| Idempotent invoice creation | ✅ Invoice.createIdempotent() | Done |
| Immutable audit logs (block update/delete) | ✅ Schema pre-hooks | Done |
| Transaction atomicity (multi-doc) | ✅ mongoose sessions | Done |
| Compound unique index (invoice amount) | ✅ uniqueAmount+walletAddress | Done |
| Double-entry ledger | ❌ Phase 2 | 🔴 |
| Ledger reconciliation job | ❌ Phase 2 | 🔴 |

---

## DOMAIN 10 — CRYPTOGRAPHY & KEY MANAGEMENT

### 10.1 Key Management
| Control | Status | Priority |
|---------|--------|----------|
| Master key from ENV (never in DB) | ✅ | Done |
| Master key: 256-bit entropy enforced | ✅ CONFIG validator | Done |
| All 4 secrets must be distinct | ✅ CONFIG validator | Done |
| Master key deleted from process.env after startup | ✅ server.js SC-3 | Done |
| AES-256-GCM encryption (AEAD) | ✅ encryption.js | Done |
| Random IV per encryption | ✅ randomBytes(12) per call | Done |
| Private key returned as Buffer (zeroable) | ✅ E1 fix | Done |
| Master key rotation | ❌ No rotation mechanism | 🔴🏦 |
| HSM for master key | ❌ Software only | 🔴🏦 |
| Key derivation per wallet (KDF) | ⚠️ Per-wallet encrypted keys | 🟠 |
| Key versioning (old key decryption) | ❌ Single version | 🟠 |

### 10.2 Randomness & Hashing
| Control | Status | Priority |
|---------|--------|----------|
| CSPRNG for all tokens | ✅ crypto.randomBytes | Done |
| SHA-256 for token hashing | ✅ | Done |
| Timing-safe comparison | ✅ timingSafeEqual | Done |
| UUID v4 for nonces | ✅ | Done |
| Entropy validation (all secrets 64 hex) | ✅ | Done |
| Custom PRNG forbidden | ✅ Never used | Done |

### 10.3 Signing & Verification
| Control | Status | Priority |
|---------|--------|----------|
| HMAC-SHA256 for merchant API | ✅ | Done |
| HMAC-SHA256 for outbound webhooks | ✅ webhookSigner.js | Done |
| Webhook replay protection (5min window) | ✅ t= timestamp | Done |
| Digital signature (blockchain TX) | ❌ Signing service (Phase 2) | 🔴 |
| Multi-signature for large withdrawals | ❌ Phase 3 | 🏦 |
| Transaction signing in isolated process | ❌ Phase 2 | 🔴🏦 |
| Post-quantum algorithm readiness | ❌ Algorithm agility design needed | 🏦 |

---

## DOMAIN 11 — MEMORY & PROCESS SECURITY

| Attack | Status | Priority |
|--------|--------|----------|
| Private key in string (can't zero) | ✅ Returns Buffer now | Done |
| Master key too long in memory | ✅ E2: zeroed after validation | Done |
| Secrets in process.env after startup | ✅ Deleted in server.js | Done |
| Heap dump exposes secrets | ⚠️ Buffer helps; HSM eliminates | 🟠🏦 |
| Core dump contains keys | ❌ OS-level: disable core dumps | 🟠 |
| Memory swapped to disk (swap) | ❌ Disable swap or encrypt swap | 🟠🏦 |
| ASLR (Address Space Layout Randomization) | ✅ Node.js inherits OS ASLR | Done |
| CPU speculative execution (Spectre/Meltdown) | ❌ OS patches + process isolation | 🏦 |
| Process isolation (key ops) | ❌ Signing service Phase 2 | 🔴🏦 |
| Separate OS user per service | ❌ Deployment config | 🟠 |
| PM2 memory limits (OOM killer) | ✅ ecosystem.config.js 512MB | Done |
| Buffer overflow (Node native addons) | ✅ No native addons | Done |
| Prototype pollution at runtime | ✅ Object.freeze for config | Done |

---

## DOMAIN 12 — INFRASTRUCTURE & CLOUD SECURITY

### 12.1 Deployment Security
| Control | Status | Priority |
|---------|--------|----------|
| Environment separation (dev/staging/prod) | ❌ Not deployed | 🔴 |
| Secrets management (Vault/AWS SM) | ❌ Using .env files | 🔴🏦 |
| Container security (Docker hardening) | ❌ No containers yet | 🟠 |
| Container image scanning | ❌ | 🟠 |
| No root in containers | ❌ Deployment | 🟠 |
| Read-only filesystem for containers | ❌ Deployment | 🟠 |
| Kubernetes RBAC | ❌ If using K8s | 🟠 |
| Pod security policies | ❌ If using K8s | 🟠 |
| Network policies (K8s) | ❌ | 🟠 |
| Service mesh (mTLS interservice) | ❌ Istio/Linkerd | 🔴🏦 |
| IDS/IPS (intrusion detection) | ❌ Cloud provider IDS | 🟠 |
| SIEM (Security Event Management) | ❌ Datadog / Splunk | 🟠🏦 |

### 12.2 CI/CD Pipeline Security
| Control | Status | Priority |
|---------|--------|----------|
| npm ci (lockfile strict) | ✅ script added | Done |
| npm audit (CI gate) | ✅ audit:critical script | Done |
| Dependency vulnerability scanning | ⚠️ Manual; needs Dependabot | 🟠 |
| SBOM (Software Bill of Materials) | ❌ Syft / CycloneDX | 🟠 |
| Code signing (commits) | ❌ GPG sign commits | 🟡 |
| Pipeline secrets management | ❌ GitHub Actions secrets | 🟠 |
| Branch protection (main) | ❌ GitHub settings | 🟠 |
| Required code review | ❌ GitHub settings | 🟠 |
| SAST (Static Analysis) | ❌ Semgrep / Snyk | 🟠 |
| DAST (Dynamic Analysis) | ❌ OWASP ZAP | 🟠 |
| Secret scanning in commits | ❌ GitGuardian / truffleHog | 🔴 |
| Artifact signing | ❌ Sigstore / cosign | 🟡 |

### 12.3 Cloud Security
| Control | Status | Priority |
|---------|--------|----------|
| VPC private subnets | ❌ Deployment | 🔴 |
| Security groups (least-privilege ports) | ❌ Deployment | 🔴 |
| No public IPs on DB/internal services | ❌ Deployment | 🔴 |
| Cloudflare WAF + DDoS | ❌ DNS config | 🔴 |
| AWS Shield / GCP Cloud Armor | ❌ | 🟠 |
| Cloud IAM least privilege | ❌ | 🟠 |
| No hardcoded cloud credentials | ✅ Using ENV vars | Done |
| Cloud audit logging (CloudTrail) | ❌ AWS config | 🟠 |
| S3 bucket public access blocked | ❌ Deployment | 🟠 |
| Backup to separate cloud account | ❌ | 🟡 |

---

## DOMAIN 13 — SUPPLY CHAIN SECURITY

| Attack | Status | Priority |
|--------|--------|----------|
| Typosquatting (malicious npm package) | ⚠️ Use npm audit; need Dependabot | 🟠 |
| Dependency confusion (internal pkg name) | ❌ npm scope + private registry | 🟡 |
| Compromised dependency | ⚠️ npm audit; no lockfile verification | 🟠 |
| Malicious package reads process.env | ✅ Secrets deleted from env after startup | Done |
| Build pipeline compromise | ❌ Pipeline security controls | 🟠 |
| Compromised base Docker image | ❌ Image scanning + digest pinning | 🟠 |
| Third-party SDK compromise (otplib etc.) | ⚠️ npm audit covers known CVEs | 🟠 |
| License compliance (viral licenses) | ❌ License scanner (FOSSA) | 🟡 |

---

## DOMAIN 14 — FRONTEND SECURITY (PHASE 2+)

> **Note:** No frontend built yet. These must all be implemented when dashboard is built.

| Control | Priority |
|---------|----------|
| Content Security Policy (strict, nonce-based) | 🔴 |
| Subresource Integrity (SRI) for all external JS/CSS | 🔴 |
| No secrets in client-side code / ENV | 🔴 |
| No sensitive data in localStorage (use memory) | 🔴 |
| No sensitive data in URL params | 🔴 |
| Sanitize all rendered data (DOMPurify / escaping) | 🔴 |
| React: dangerouslySetInnerHTML never used | 🔴 |
| Secure PostMessage origin validation | 🟠 |
| Service Worker security (fetch event) | 🟠 |
| Browser extension isolation | 🟠 |
| Clickjacking via frameAncestors | ✅ Already in CSP | Done |
| Autocomplete=off on payment fields | 🟡 |
| Clipboard hijacking protection | 🟡 |
| Drag-and-drop data exfiltration | 🟡 |
| Keylogger via malicious browser extension | 🟡 |
| QR code scanning (safe URLs only) | 🟠 |
| WebCrypto API for client-side ops | 🟡 |

---

## DOMAIN 15 — BLOCKCHAIN & CRYPTO-SPECIFIC SECURITY

| Attack | Status | Priority |
|--------|--------|----------|
| Private key exposure (plaintext) | ✅ AES-256-GCM encrypted | Done |
| Private key in memory too long | ✅ Buffer + zeroed after use | Done |
| Signing in same process as HTTP | ❌ Signing service Phase 2 | 🔴🏦 |
| Multi-signature for large txns | ❌ Phase 3 | 🏦 |
| Cold storage for reserves | ❌ Business decision | 🏦 |
| Transaction replay (wrong chain ID) | ❌ Network check on signing | 🟠 |
| Transaction malleability | ⚠️ TRC20 USDT: managed by protocol | 🟡 |
| Double-spend detection | ❌ Minimum confirmation depth | 🔴 |
| 0-confirmation acceptance | ❌ Must require 19+ confirmations (Tron) | 🔴 |
| Fake deposit attack | ❌ Matching + confirm depth | 🔴 |
| Dust attack | ❌ Min amount validation | 🟠 |
| Address validation (checksum) | ✅ TRC20 regex + Joi | Done |
| Unique amount collision (matching engine) | ✅ Compound unique index | Done |
| TronGrid API spoofing | ✅ URL allowlist in config | Done |
| TronGrid API no cert pinning | ❌ Phase 2 | 🟠 |
| Front-running (miner priority) | ❌ N/A for USDT TRC20 | Done |
| Oracle manipulation | ❌ N/A for fixed-rate USDT | Done |
| Gas price manipulation | ❌ Energy/bandwidth model (Tron) | 🟡 |
| Withdrawal without cooling-off | ❌ Phase 2 (1hr minimum) | 🔴 |
| No per-merchant withdrawal cap | ❌ Phase 2 | 🔴 |
| Unlimited withdrawal retry | ❌ Phase 2 | 🔴 |

---

## DOMAIN 16 — PHYSICAL & HARDWARE SECURITY

> These are operational requirements for production. Out of code scope.

| Control | Requirement | Priority |
|---------|-------------|----------|
| HSM for master encryption key | AWS CloudHSM / Vault HSM | 🔴🏦 |
| HSM for TLS private key | Hardware-stored TLS cert | 🟠🏦 |
| HSM for signing service | Thales / Gemalto HSM | 🔴🏦 |
| Physical server access control | Biometric + CCTV | 🏦 |
| Hardware security key for admin access | YubiKey FIDO2 | 🟠🏦 |
| Encrypted laptops (developer machines) | BitLocker / FileVault | 🟠 |
| Screen lock policies | MDM policy | 🟠 |
| USB port disable on servers | BIOS/OS policy | 🟡 |
| Secure disposal of hardware | NIST 800-88 media sanitization | 🟡 |

---

## DOMAIN 17 — IAM & PRIVILEGED ACCESS MANAGEMENT

| Control | Status | Priority |
|---------|--------|----------|
| Least privilege (DB users per service) | ❌ | 🔴 |
| Just-in-time access (no standing admin access) | ❌ Vault dynamic secrets | 🏦 |
| Admin access requires 2FA | ❌ Enforced at app level | 🟠 |
| Admin access via VPN only | ❌ Infra | 🟠 |
| Developer access to production blocked | ❌ Infra | 🟠🏦 |
| Service accounts rotated regularly | ❌ | 🟠 |
| Break-glass accounts (emergency) | ❌ | 🟡🏦 |
| Privileged session recording | ❌ PAM tool | 🏦 |
| Separation of duties (finance vs ops) | ❌ Multi-person for withdrawals | 🔴🏦 |

---

## DOMAIN 18 — MONITORING, DETECTION & INCIDENT RESPONSE

### 18.1 Monitoring
| Control | Status | Priority |
|---------|--------|----------|
| Structured JSON logging | ✅ logger.js | Done |
| Request ID tracing | ✅ x-request-id | Done |
| Async context propagation | ✅ requestContextMiddleware | Done |
| Immutable audit logs | ✅ AuditLog model | Done |
| Auth anomaly detection (new IP login) | ✅ S-4 implemented | Done |
| Refresh token context change warning | ✅ S-3 implemented | Done |
| IP prefix mismatch warning (JWT) | ✅ T-1 implemented | Done |
| SIEM integration | ❌ Splunk/Datadog | 🟠🏦 |
| Real-time alerting (PagerDuty) | ❌ | 🟠🏦 |
| Velocity detection (fraud) | ❌ Phase 2 | 🟠 |
| Unusual transaction pattern detection | ❌ Phase 2 | 🟠 |
| Dark web credential monitoring | ❌ Third-party service | 🟡🏦 |

### 18.2 Incident Response
| Control | Status | Priority |
|---------|--------|----------|
| Incident response plan | ❌ Document needed | 🔴 |
| Key revocation procedure | ❌ Document needed | 🔴 |
| LogoutAll endpoint (revoke all sessions) | ✅ authController.js | Done |
| Account freeze capability | ✅ isActive=false | Done |
| Emergency key rotation | ❌ No mechanism | 🔴🏦 |
| Forensic logging (enough detail) | ✅ Audit log with before/after | Done |
| Data breach notification procedure | ❌ GDPR required | 🟠 |

---

## DOMAIN 19 — COMPLIANCE & REGULATORY

| Requirement | Applicability | Status | Priority |
|-------------|--------------|--------|----------|
| PCI-DSS Level 1 | Required for card payments | ❌ N/A (crypto only) | 🏦 |
| PCI-DSS Level 3/4 | If card-adjacent | ❌ Assessment needed | 🏦 |
| AML / KYC | Required for money transmission | ❌ Phase 2 | 🔴🏦 |
| FATF Travel Rule | Crypto $1000+ | ❌ Phase 2 | 🔴🏦 |
| GDPR / Data Protection | EU users | ❌ Data deletion not built | 🟠 |
| CCPA | California users | ❌ | 🟡 |
| Data retention policy | Legal requirement | ❌ | 🟠 |
| Right to erasure | GDPR Article 17 | ❌ | 🟠 |
| SOC 2 Type II | Customer trust | ❌ Needs 6-month audit period | 🏦 |
| ISO 27001 | Information security | ❌ Needs 12-month cycle | 🏦 |
| Money transmission license | Required by jurisdiction | ❌ Legal team | 🔴🏦 |
| Bug bounty program | Responsible disclosure | ❌ HackerOne / Bugcrowd | 🟡 |
| Penetration test (annual) | PCI/SOC requirement | ❌ CREST-certified tester | 🟠🏦 |
| Vulnerability disclosure policy | Legal protection | ❌ security.txt | 🟡 |

---

## DOMAIN 20 — SOCIAL ENGINEERING & HUMAN FACTORS

| Attack | Mitigation | Status |
|--------|-----------|--------|
| Phishing (admin credentials) | Hardware 2FA + security training | ❌ |
| Spear phishing (targeted email) | Email DMARC/DKIM/SPF | ❌ |
| Vishing (phone impersonation) | No phone support policy + callback verification | ❌ |
| SIM swapping (SMS 2FA bypass) | ✅ No SMS 2FA implemented | Done |
| Insider threat | Least privilege + audit logs | ⚠️ Partial |
| Social media OSINT | Employee security training | ❌ |
| CEO fraud (BEC) | Multi-person approval for transfers | ❌ |
| Fake support impersonation | Clear support channel policy | ❌ |
| Developer workstation compromise | EDR + encrypted disk | ❌ |

---

## DOMAIN 21 — BUSINESS CONTINUITY & DISASTER RECOVERY

| Control | Status | Priority |
|---------|--------|----------|
| Database backup (automated daily) | ❌ | 🔴 |
| Backup encryption | ❌ | 🔴 |
| Backup restore testing | ❌ | 🔴 |
| RTO target (Recovery Time Objective) | ❌ Define: < 1 hour | 🟠 |
| RPO target (Recovery Point Objective) | ❌ Define: < 15 minutes | 🟠 |
| Multi-region failover | ❌ | 🏦 |
| Hot standby DB replica | ❌ MongoDB Atlas replica set | 🟠 |
| Graceful shutdown handler | ✅ server.js SIGTERM/SIGINT | Done |
| Circuit breaker pattern | ❌ Phase 2 | 🟠 |
| Chaos engineering tests | ❌ | 🏦 |
| Runbook documentation | ❌ | 🟠 |

---

## DOMAIN 22 — QUANTUM COMPUTING THREATS

| Threat | Impact | Mitigation | Status |
|--------|--------|-----------|--------|
| Shor's algorithm breaks RSA/ECC | Private key recovery | Post-quantum crypto (CRYSTALS-Kyber) | ❌ |
| Grover's algorithm weakens AES-128 | AES-256 still safe | ✅ Using AES-256-GCM | Done |
| Harvest now, decrypt later (HNDL) | Future decryption of today's data | Algorithm agility in design | ❌ |
| NIST PQC standards (2024) | New algorithm standards | Migration plan needed | ❌ |
| Timeline estimate | ~10-15 years for cryptographically relevant quantum | Begin migration planning | 🟡 |

---

## STATUS SUMMARY DASHBOARD

```
DOMAIN                          IMPLEMENTED   PARTIAL   MISSING
─────────────────────────────────────────────────────────────
1. Network & Transport               40%        20%       40%
2. Authentication                    75%        10%       15%
3. Session & Token                   85%         5%       10%
4. Authorization                     80%        10%       10%
5. Injection (all types)             85%         5%       10%
6. XSS                               60%         0%       40%
7. CSRF & UI                         90%         5%        5%
8. API Security                      80%        10%       10%
9. Database Security                 60%         5%       35%
10. Cryptography                     70%        10%       20%
11. Memory & Process                 65%        10%       25%
12. Infrastructure                   15%         0%       85%
13. Supply Chain                     40%        20%       40%
14. Frontend                          5%         0%       95%
15. Blockchain-Specific              50%         5%       45%
16. Physical & Hardware               0%         0%      100%
17. IAM & PAM                        20%         0%       80%
18. Monitoring & Detection           55%         5%       40%
19. Compliance                        5%         0%       95%
20. Social Engineering                5%        10%       85%
21. Business Continuity              10%         0%       90%
22. Quantum Computing                10%         0%       90%
─────────────────────────────────────────────────────────────
OVERALL CODE SECURITY:              ~80% done
OVERALL SYSTEM SECURITY:            ~35% done (infra missing)
BANK-GRADE COMPLETE:                ~20% done (needs HSM + compliance)
```

---

## IMPLEMENTATION ROADMAP

### 🔴 PHASE 2A — Must Do Before Handling Real Money (4 weeks)
1. **Signing service** — isolate key ops into separate process (queue-based)
2. **Redis HA** — Redis Sentinel / Cluster for rate limit persistence
3. **Minimum blockchain confirmations** — 19+ for Tron before crediting
4. **Withdrawal cooling-off period** — 1 hour minimum
5. **Per-merchant withdrawal limits** — daily cap in Merchant model
6. **2FA mandatory** — enforce for all merchant accounts
7. **Secret scanning** — GitGuardian in CI pipeline
8. **Testnet full simulation** — wrong amounts, replay, double-pay, delayed tx
9. **Double-entry ledger** — every credit/debit as paired entries

### 🟠 PHASE 2B — Scale-Ready Security (8 weeks)
1. **Cloudflare WAF** — L7 filtering, DDoS protection, geo-blocking
2. **HashiCorp Vault** — secrets management (replace .env files)
3. **MongoDB Atlas** — encryption at rest, VPC peering, replica set
4. **TLS 1.3 only** — Nginx cipher config
5. **mTLS** — interservice communication
6. **Separate DB users** per service with least privilege
7. **SIEM** — Datadog / Splunk for real-time security monitoring
8. **Dependabot** — automated dependency updates
9. **SAST** — Semgrep in CI pipeline
10. **KYC/AML** — basic identity verification before merchant activation

### 🏦 PHASE 3 — True Bank-Grade (6 months)
1. **HSM** — AWS CloudHSM for master encryption key
2. **Signing service with HSM** — private keys never leave hardware
3. **Multi-signature** — 2-of-3 for withdrawals above threshold
4. **Cold storage** — 90%+ reserves in offline wallets
5. **PCI-DSS assessment** (if card-adjacent)
6. **SOC 2 Type II** — 6-month audit window
7. **ISO 27001** — information security management system
8. **AML/KYC** — full compliance implementation
9. **Money transmission license** — jurisdiction-specific
10. **External penetration test** — CREST-certified, annual
11. **Bug bounty program** — HackerOne / Bugcrowd
12. **Post-quantum crypto readiness** — algorithm agility

---

## RESOURCES & STANDARDS REFERENCES

| Standard | URL |
|----------|-----|
| OWASP Top 10 | owasp.org/Top10 |
| OWASP API Security Top 10 | owasp.org/API-Security |
| NIST Cybersecurity Framework | nist.gov/cyberframework |
| PCI-DSS v4.0 | pcisecuritystandards.org |
| NIST SP 800-63B (Auth) | pages.nist.gov/800-63-3 |
| CWE Top 25 | cwe.mitre.org/top25 |
| MITRE ATT&CK | attack.mitre.org |
| NIST PQC Standards | csrc.nist.gov/pqc |
| FATF Crypto Guidance | fatf-gafi.org |
| ISO 27001 | iso.org/isoiec-27001 |
| SOC 2 | aicpa.org/soc2 |
| MongoDB Security | docs.mongodb.com/security |
| Node.js Security | nodejs.org/security |
| OWASP Cryptographic Failures | owasp.org/A02 |

---

*This document covers 200+ security controls across 22 domains.
True bank-grade security is a continuous process — not a destination.*
*Last updated: 2026-04-03 | XCoinGateway Security Team*
