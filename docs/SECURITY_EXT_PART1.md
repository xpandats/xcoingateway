# XCoinGateway — Extended Security Reference — Part 1 of 3
## Domains 23–32 | INTERNAL CONFIDENTIAL

---

## DOMAIN 23 — TIMING & SIDE-CHANNEL ATTACKS

| Attack | Description | Status | Priority |
|--------|-------------|--------|----------|
| Login timing oracle | Response time differs for valid vs invalid user | ✅ always bcrypt | Done |
| Registration timing oracle | Fast return if email exists vs slow bcrypt | ✅ always bcrypt both paths | Done |
| Refresh token timing oracle | Found vs revoked takes different time | ✅ constant-time path | Done |
| HMAC comparison timing | String == leaks via early exit | ✅ timingSafeEqual everywhere | Done |
| Password reset timing | Expiry check before DB lookup | ❌ Phase 2 when reset built | 🟠 |
| CPU cache timing (Spectre) | Speculative execution leaks secrets | ❌ OS patches + process isolation | 🏦 |
| Network timing oracle | Attacker infers hit/miss via RTT | ⚠️ needs response jitter (Phase 2) | 🟡 |
| Padding oracle (AES-CBC) | Decrypt any ciphertext via error | ✅ Using AES-GCM (authenticated) | Done |
| Compression + TLS (CRIME/BREACH) | Recover plaintext via compression ratio | ✅ Disable HTTP compression on secrets | 🟡 |
| Branch prediction timing | Side-channel via CPU branch predictor | ❌ OS/hardware level | 🏦 |
| Memory access timing (Flush+Reload) | Infer keys from LLC cache state | ❌ HSM eliminates | 🏦 |
| Acoustic/power side-channel | Physical key extraction | ❌ HSM eliminates | 🏦 |

---

## DOMAIN 24 — RACE CONDITIONS & CONCURRENCY

| Attack | Description | Status | Priority |
|--------|-------------|--------|----------|
| TOCTOU — balance read then debit | Check balance, then withdraw, balance changes between | ✅ atomic $inc / transactions | Done |
| TOCTOU — invoice duplicate creation | Create invoice twice concurrently = same uniqueAmount | ✅ compound unique index | Done |
| Concurrent withdrawal requests | Two withdrawals simultaneously deplete balance twice | ❌ Withdrawal engine Phase 2 (needs DB lock) | 🔴 |
| Concurrent 2FA enable/verify | Two requests race on twoFactorSecret | ❌ Needs atomic compare-and-swap | 🟠 |
| Session creation race | Two logins at exact same ms create two sessions | ✅ atomic session eviction | Done |
| Refresh token rotation race | Two refreshes simultaneously get valid tokens | ✅ atomic rotation in transaction | Done |
| Idempotency key race | Two identical keys submitted at the same instant | ✅ MongoDB unique index on idempotencyKey | Done |
| Redis lock expiry during operation | Lock expires before long op completes | ❌ Redlock algorithm needed | 🟠 |
| Optimistic vs pessimistic locking | MongoDB findOneAndUpdate vs transactions | ⚠️ mix of both; need audit | 🟠 |
| Distributed race (multi-instance) | Two pods process same webhook simultaneously | ❌ Redis distributed lock | 🔴 |
| Event ordering (blockchain) | Two transactions confirmed out of order | ❌ Sequence number tracking Phase 2 | 🔴 |
| Double-spend via race | Submit withdraw + invoice payment simultaneously | ❌ unified ledger lock Phase 2 | 🔴 |
| ABA problem (compare-and-swap) | Value changes A→B→A, looks unchanged | ❌ Version field (optimistic lock) | 🟠 |

---

## DOMAIN 25 — SERIALIZATION & DESERIALIZATION

| Attack | Description | Status | Priority |
|--------|-------------|--------|----------|
| JSON prototype pollution | `{"__proto__":{"isAdmin":true}}` | ✅ noSqlSanitize blocks prototype keys | Done |
| BSON type injection | Sending ObjectId type as raw bytes | ✅ validateObjectId() wraps all | Done |
| Type coercion bypass | `"1" == 1` in loose comparison | ✅ Joi validates type explicitly | Done |
| JSON number precision loss | `9007199254740993` → wrong integer | ✅ money.js uses BigInt | Done |
| Insecure deserialization | node-serialize / YAML.load code execution | ✅ Neither lib used | Done |
| XML deserialization / XXE | XML entity expansion to read files | ✅ No XML parser used | Done |
| YAML deserialization | js-yaml unsafe load | ✅ No YAML deserialization | Done |
| MessagePack injection | Binary protocol injection | ✅ JSON only (express.json) | Done |
| Circular reference DoS | `JSON.stringify` hangs on circular | ✅ No user-supplied objects serialized | Done |
| Large payload DoS | 100MB JSON body | ✅ Body size limits 10kb/100kb | Done |
| Array flooding | `{ arr: [1,1,1,...million] }` | ✅ Body size limit catches it | Done |
| Deeply nested object | Stack overflow via 1000x nesting | ❌ Add JSON depth limit middleware | 🟠 |
| RegExp via data | User sends regex string, app uses /userInput/ | ⚠️ Must never use user input as regex | 🟠 |

---

## DOMAIN 26 — ENCODING & UNICODE ATTACKS

| Attack | Description | Status | Priority |
|--------|-------------|--------|----------|
| URL double encoding | `%252F` → `%2F` → `/` bypasses path check | ✅ Express decodes once; Joi validates after | Done |
| Null byte injection | `admin\0.jpg` treated as `admin` by C libs | ✅ safeFilePath strips null bytes | Done |
| Unicode normalization bypass | `ﬁle` (ligature) normalizes to `file` | ❌ Normalize all strings to NFC/NFKC before validation | 🟠 |
| Homoglyph attack | `аdmin` (Cyrillic а looks like Latin a) | ❌ Block non-ASCII in identifiers | 🟠 |
| Bidirectional text (RTL override) | `\u202E` reverses text display in UI | ❌ Strip control characters | 🟠 |
| Zero-width characters | `ad\u200Bmin` passes filter but renders as `admin` | ❌ Strip zero-width chars | 🟠 |
| Overlong UTF-8 | Non-shortest form encodes `/` as `\xc0\xaf` | ✅ Node.js rejects in URL parsing | Done |
| UTF-7 XSS (legacy) | `+ADw-script+AD4-` in old IE/Outlook | ✅ Content-Type enforced | Done |
| HTML entity bypass | `&lt;script&gt;` rendering in some contexts | ✅ API only, no HTML output | Done |
| Case folding bypass | `SELECT` vs `sElEcT` in blocklists | ✅ Mongoose parameterized, no blocklists | Done |
| Unicode in email address | `user@аmazon.com` (Cyrillic а) | ❌ Normalize + validate email IDN | 🟠 |
| Base64 side effects | Padding `=` causes unexpected parsing | ✅ Base64 not used for user input | Done |
| Path separator normalization | `\` vs `/` on Windows vs Linux | ✅ path.resolve() normalizes | Done |

---

## DOMAIN 27 — HTTP PROTOCOL ATTACKS

| Attack | Description | Status | Priority |
|--------|-------------|--------|----------|
| HTTP Request Smuggling CL-TE | Conflicting Content-Length + Transfer-Encoding | ✅ reject if both headers present | Done |
| HTTP Request Smuggling TE-CL | Reverse case | ✅ Same rejection | Done |
| HTTP Request Smuggling TE-TE | Both present but obfuscated | ❌ Nginx must normalize (final gate) | 🔴 |
| HTTP Response Splitting | Inject `\r\n` into response headers | ✅ No user values in response headers | Done |
| Host header injection | `Host: evil.com` used in redirect/email | ❌ Validate Host against allowlist | 🟠 |
| X-Forwarded-For spoofing | Fake IP to bypass rate limit | ⚠️ trust proxy:1 set; need Nginx to strip | 🟠 |
| X-Original-URL override | Nginx proxy bypass via header | ❌ Strip X-Original-URL at Nginx | 🟠 |
| HTTP method override | `X-HTTP-Method-Override: DELETE` | ❌ Reject this header explicitly | 🟠 |
| Verb tampering | PUT instead of POST bypasses middleware | ⚠️ Route-specific; need OPTIONS audit | 🟡 |
| HTTP/2 rapid reset (CVE-2023-44487) | DoS via rapid SETTINGS/RST_STREAM | ❌ Nginx/server upgrade + Cloudflare | 🔴 |
| HTTP pipelining attacks | Multiple requests in one TCP connection | ✅ Express handles HTTP/1.1 pipelining | Done |
| Chunked encoding abuse | Malformed chunk size causes parser confusion | ❌ Nginx + strict body parser | 🟠 |
| Header size flooding | 1000 headers per request | ❌ Nginx max_headers=100 needed | 🟠 |
| Large cookie flooding | 64KB Cookie header | ❌ Nginx large_client_header_buffers | 🟠 |
| HTTP/2 header compression (HPACK) | Table poisoning | ❌ Nginx HTTP/2 config | 🟡 |
| Trailer injection (HTTP/1.1) | Trailers used to inject additional headers | ❌ Nginx strips trailers | 🟡 |

---

## DOMAIN 28 — CACHE SECURITY

| Attack | Description | Status | Priority |
|--------|-------------|--------|----------|
| Cache poisoning | Inject evil response into shared cache | ❌ Cache-Control: no-store on auth | 🟠 |
| Web cache deception | `GET /account.css` → cached private data | ❌ Vary: Cookie + no-cache on all API responses | 🟠 |
| CDN cache bypass | `?cachebuster=rand` shows secret response | ❌ CDN config: never cache auth responses | 🟠 |
| Cache key normalization | `GET /api/v1/user` vs `/api/v1/user ` different cache keys | ❌ CDN key normalization | 🟡 |
| Response caching sensitive data | Browser caches auth response | ❌ Add Cache-Control: no-store to all API responses | 🟠 |
| Redis cache poisoning | Attacker writes to Redis if misconfigured | ❌ Redis auth + private network only | 🔴 |
| Redis key enumeration | KEYS * dumps all data | ❌ Disable KEYS command in Redis | 🟠 |
| Redis FLUSHALL | Attacker clears all rate limit data | ❌ Redis ACL lists | 🟠 |
| Shared cache between tenants | Merchant A reads Merchant B cache | ❌ Namespace cache keys with merchantId | 🔴 |
| Stale-while-revalidate abuse | Attackers use stale auth responses | ❌ No stale allowed on auth | 🟡 |

---

## DOMAIN 29 — ACCESS CONTROL BYPASS TECHNIQUES

| Bypass Technique | Description | Status | Priority |
|-----------------|-------------|--------|----------|
| Path traversal to admin | `/api/v1/user/../admin/users` | ✅ Express normalizes paths | Done |
| Double URL encode path | `/api/v1/%2e%2e/admin` | ✅ Express decodes before routing | Done |
| Case sensitivity bypass | `/API/V1/Auth/Login` vs `/api/v1/auth/login` | ✅ Express case-sensitive:false by default | Done |
| Trailing slash bypass | `/api/v1/admin/` vs `/api/v1/admin` | ✅ Express treats same | Done |
| Fragment bypass | `/admin#ignoredpart` | ✅ Fragments not sent to server | Done |
| Parameter pollution bypass | `role=merchant&role=admin` | ✅ hpp middleware, takes first | Done |
| Content negotiation bypass | `Accept: text/html` changes response | ✅ JSON only output | Done |
| X-Custom-IP-Authorization | Fake header to spoof trusted IP | ✅ Only trust proxy:1, not custom headers | Done |
| Referer-based access | Access restricted by Referer header | ✅ Not using Referer for auth | Done |
| JWT algorithm none | `{"alg":"none"}` | ✅ algorithms:['HS256'] pinned | Done |
| JWT role manipulation | Decode/re-encode with changed role | ✅ DB role fetched on every request | Done |
| Cookie attribute bypass | HttpOnly bypass via XSS → moot | ✅ XSS prevented at CSP level | Done |
| Host header to admin panel | `Host: internal.admin` triggers different route | ❌ Validate Host header strictly | 🟠 |
| IP allowlist bypass via proxy | Send X-Forwarded-For: 127.0.0.1 | ⚠️ trust proxy:1 limits this | 🟠 |
| API versioning bypass | `/api/v0/auth` still active unprotected | ❌ Audit all route versions | 🟠 |
| OPTIONS pre-flight bypass | CORS pre-flight may miss auth check | ✅ OPTIONS handled by cors() properly | Done |

---

## DOMAIN 30 — CONFIGURATION & ENVIRONMENT SECURITY

| Issue | Description | Status | Priority |
|-------|-------------|--------|----------|
| Default credentials left | MongoDB/Redis has no auth | ✅ Config validator requires auth | Done |
| Debug mode in production | NODE_ENV=development on prod | ✅ Stack traces hidden in production | Done |
| X-Powered-By header | Exposes Express version | ✅ Helmet removes it | Done |
| Server version in headers | nginx/1.24.0 in Server header | ❌ Nginx config: server_tokens off | 🟠 |
| Directory listing enabled | Nginx autoindex on | ❌ Nginx config: autoindex off | 🟠 |
| Unnecessary HTTP methods | TRACE/CONNECT enabled | ❌ Nginx: only allow GET/POST/etc. | 🟠 |
| CORS wildcard (*) | Access-Control-Allow-Origin: * | ✅ Strict allowlist not wildcard | Done |
| Open ports | MongoDB 27017 publicly reachable | ❌ Security groups / firewall | 🔴 |
| Redis ports exposed | 6379 publicly reachable | ❌ Security groups / VPC only | 🔴 |
| .env file in repo | Secrets committed | ✅ .gitignore covers .env* | Done |
| .env file readable on server | World-readable permissions | ❌ chmod 600 .env files | 🟠 |
| Swagger/OpenAPI exposed | Route docs exposed publicly | ❌ Auth-gate or remove in prod | 🟠 |
| Error logging verbosity | Debug logs in production | ✅ Level=warn in production | Done |
| Config hot-reload without restart | ENV changes applied live by accident | ✅ Config read at startup only | Done |
| NODE_PATH pollution | Relative require() resolves unintended modules | ✅ Workspaces explicit paths | Done |
| prototype.js pollution via npm | A dep pollutes Object.prototype | ✅ blocked at noSqlSanitize + safeFilePath | Done |

---

## DOMAIN 31 — ERROR HANDLING & INFORMATION DISCLOSURE

| Leak Type | Description | Status | Priority |
|-----------|-------------|--------|----------|
| Stack traces to client | `at authService.js:245` | ✅ Hidden in production | Done |
| MongoDB error messages | `E11000 duplicate key error collection: xcg.users` | ✅ AppError wraps all DB errors | Done |
| Mongoose CastError paths | `Cast to ObjectId failed for value "abc" at path "_id"` | ✅ Sanitized in logger | Done |
| Internal IP in errors | `connect ECONNREFUSED 10.0.1.5:27017` | ⚠️ Caught by global error handler, need audit | 🟠 |
| Auth state machine exposure | Different error codes per auth failure step | ✅ AUTH_ERROR in production | Done |
| Timing difference as signal | 100ms vs 500ms response time leaks state | ✅ Timing fixes applied | Done |
| Dependency version in error | `jsonwebtoken@9.0.3` in stack | ✅ Hidden in production | Done |
| File system path in error | `ENOENT: /home/ubuntu/app/keys/master.key` | ❌ Need error message sanitization for FS errors | 🟠 |
| Database schema in error | Field names in validation errors | ✅ Joi errors use field aliases | Done |
| Regex error detail | ReDoS exposes regex pattern | ✅ Regex removed; no user pattern | Done |
| 404 path echo | `Cannot GET /api/v1/secreet` | ✅ Generic 404 message only | Done |
| User count inference | "User #40523" implies user base size | ❌ Use UUIDs not sequential IDs | 🟡 |
| Rate limit counter in header | `X-RateLimit-Remaining: 1` leaks limit config | ⚠️ Currently standard-rate-limit headers returned | 🟡 |
| Audit log exposure in API | API returns full audit entries | ❌ Audit log must not be API-accessible to merchants | 🟠 |

---

## DOMAIN 32 — CRYPTOGRAPHIC PROTOCOL ATTACKS

| Attack | Algorithm Affected | Status | Priority |
|--------|-------------------|--------|----------|
| Padding oracle | AES-CBC | ✅ Using AES-GCM (no padding oracle possible) | Done |
| BEAST | TLS 1.0 CBC | ✅ TLS 1.0 not used (needs Nginx config) | 🟠 |
| POODLE | SSL 3.0 | ✅ SSL 3.0 disabled | Done |
| DROWN | SSLv2 cross-protocol | ✅ Not using SSLv2 anywhere | Done |
| CRIME | TLS compression | ❌ Disable TLS compression in Nginx | 🟡 |
| BREACH | HTTP compression | ❌ Disable gzip on JSON API responses | 🟡 |
| Lucky 13 | TLS CBC timing | ✅ TLS 1.3 with AEAD eliminates | 🟠 |
| RC4 bias | RC4 stream cipher | ✅ RC4 not used | Done |
| ROBOT | RSA PKCS#1v1.5 | ✅ Not using RSA for encryption | Done |
| Bleichenbacher | RSA decryption oracle | ✅ Not using RSA | Done |
| Invalid curve (ECC) | Point not on curve | ✅ Not doing raw ECC operations | Done |
| Nonce reuse in AES-GCM | Same IV used twice = full plaintext recovery | ✅ randomBytes(12) per encryption | Done |
| Weak KDF | PBKDF2 with low iterations | ✅ bcrypt with high rounds | Done |
| Birthday attack on hash | MD5/SHA1 collision | ✅ SHA-256 only | Done |
| Length extension attack | SHA-1/SHA-256 without HMAC | ✅ All MACs use HMAC (not raw hash) | Done |
| Key commitment flaw | AES-GCM forgery without key commitment | ❌ Switch to AES-GCM-SIV for high-security contexts | 🟡 |
| Harvest now decrypt later | Encrypted today, break with quantum | ❌ Algorithm agility plan needed | 🏦 |
