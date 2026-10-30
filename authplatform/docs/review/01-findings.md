# Production-readiness review — Phase 1 findings

Review date: 2026-10-21 (Asia/Calcutta). Findings are source/configuration based unless marked Unverified. Severity order: Blocker, High, Medium, Low, Nit.

## Blocker

### B-01 — Cookie-authenticated mutations have no CSRF protection and unsafe production defaults

- Category: Security — CSRF/CORS/cookies
- Location: src/main/java/com/authplatform/common/config/SecurityConfig.java:37-38,78-99; src/main/resources/application.yml:38-45; auth controllers cookie methods.
- What is wrong: CSRF is globally disabled while console and SA access/refresh tokens authenticate from cookies. Credentialed CORS automatically allows wildcard localhost patterns. AUTH_COOKIE_SECURE defaults false. Only refresh/logout check a custom header; normal console/SA mutations do not.
- Impact: A browser request from a permitted or compromised same-site origin can use ambient cookies for state changes; production cookies can be sent over HTTP if deployment overrides are omitted.
- Evidence: csrf(csrf -> csrf.disable()); console.setAllowCredentials(true); localhost wildcard patterns; AUTH_COOKIE_SECURE:false.
- Recommended fix: Enable CSRF protection for cookie surfaces, exact-match configured origins, fail startup in prod if origins are localhost/missing or cookies are insecure, and use __Host- cookies where possible.
- Effort: L

### B-02 — JWT signing key is process-local and claim validation/key rotation is incomplete

- Category: Security — token integrity/lifecycle
- Location: src/main/java/com/authplatform/auth/service/JwtService.java:27-51,77-101.
- What is wrong: Each process start generates an RSA key in memory; there is no configured key source, retiring-key set, or rotation workflow. Parse checks issuer, audience, and expiration but does not explicitly pin alg/typ or validate nbf/iat.
- Impact: Tokens/JWKS change on restart and multi-instance verification is inconsistent. Future parser/config changes have no algorithm/claim regression guard.
- Evidence: KeyPairGenerator and RSAKey.Builder are in the constructor; parse has only issuer/audience/expiration checks; issuance pins RS256 but parse does not check the header.
- Recommended fix: Load versioned keys from a secret manager/database, publish active/retiring kid values, pin RS256/JWT type, validate nbf/iat/exp, and add tampered/none/wrong-algorithm/expired/not-before tests.
- Effort: L

## High

### H-01 — Rate limiting is not Redis sliding-window per-IP plus per-account

- Category: Security — abuse prevention
- Location: src/main/java/com/authplatform/ratelimit/RateLimitFilter.java:17-80; auth/service/LoginAttemptService.java:13-70; application.yml:45-60.
- What is wrong: Only remoteAddr plus path is limited, Redis INCR uses a fixed expiry rather than a sliding window, signup uses login capacity, configured signup/global capacities are unused, and forgot-password/resend/OTP are uncovered. Redis failures fall back to per-process maps.
- Impact: Distributed attackers can spread attempts across accounts/instances or spam reset/OTP email; Redis outage weakens global controls. Fail-open/fail-closed behavior is undocumented.
- Evidence: isLimited matches only paths ending auth/login or auth/signup; key is request.getRemoteAddr plus URI; constructor has only login settings; catch blocks use ConcurrentHashMap.
- Recommended fix: Atomic Redis sorted-set/Lua windows keyed by trusted IP and normalized account/app identity; cover all abuse-sensitive endpoints; document fail-closed auth behavior; emit retry headers and metrics.
- Effort: L

### H-02 — Developer-controlled URLs can exfiltrate verification/reset tokens

- Category: Security — unsafe token delivery
- Location: auth/service/impl/AppUserAuthServiceImpl.java:278-281; AppDtos.java:14-33; SaDtos.java:86-103.
- What is wrong: verifyEmailUrl and resetPasswordUrl are arbitrary strings concatenated with ?token= without scheme/host allowlisting or query encoding.
- Impact: A developer can set an attacker URL and cause reset/verification tokens to be emailed to that origin.
- Evidence: link() returns configured + "?token=" + token; DTO fields have no URL/custom constraint.
- Recommended fix: Validate HTTPS absolute URLs against an app-owned allowlist, reject localhost outside dev, and append query parameters via a URI builder. Add token non-leakage tests.
- Effort: M

### H-03 — Production exposure and environment separation are not enforced

- Category: Operations/security
- Location: application.yml:1-50; docker-compose.yml:1-61; README.md:9-15; .env:1-49; absence of .github workflows/Nginx/profile YAML.
- What is wrong: One config profile exposes Actuator/Swagger surfaces and security permits unmatched routes. Compose publishes Postgres, Redis, and backend ports. A local .env exists without an ignore file and contains development settings; no production fail-fast guard exists for insecure cookies. Nginx/TLS/trusted-proxy/AWS controls are absent from the workspace.
- Impact: A production deployment can expose operational metadata, databases, Redis, plaintext HTTP cookies, or development credentials. Proxy IP behavior is Unverified.
- Evidence: management endpoints include health/info/prometheus; SecurityConfig ends with anyRequest().permitAll(); Compose has Postgres/Redis ports; .env exists; find found no workflows/Nginx.
- Recommended fix: Add explicit dev/prod profiles and fail closed, bind data services privately, secure Actuator/Swagger, add .gitignore and CI secret/dependency scans, and provide deployment hardening.
- Effort: L

### H-04 — Signup and account-state responses enumerate users

- Category: Security — response uniformity
- Location: AccountAuthServiceImpl.java:59-75,104-123; AppUserAuthServiceImpl.java:69-75,119-140; ErrorCode.java:6-24.
- What is wrong: Existing signup email returns EMAIL_TAKEN/409 while new signup returns 201. Valid-password login branches expose EMAIL_NOT_VERIFIED, USER_BLOCKED, and SA-route errors. Dummy hashing only covers absent accounts.
- Impact: Attackers can enumerate developer/end-user emails and account state.
- Evidence: exists checks throw EMAIL_TAKEN; login branches throw distinct state errors; ErrorCode maps them to distinct statuses/messages.
- Recommended fix: Uniform public signup/forgot/resend responses and constant-work login outcomes; keep detail in audit/metrics. Status changes are in the decision list.
- Effort: M

### H-05 — Refresh rotation is not concurrency-safe and role changes leave stale JWT authority

- Category: Security — sessions/authorization
- Location: SessionService.java:58-67; RoleServiceImpl.java:42-56,138-150; JwtAuthenticationFilter.java:58-71; BaseEntity.java:11-31.
- What is wrong: Rotation reads then mutates without @Version/row lock/atomic compare-and-set. App-user role changes do not revoke sessions; JWT filtering trusts role claims until expiry. Redis revocation write failures are swallowed.
- Impact: Concurrent refresh can issue multiple successors. Removed permissions remain effective in existing access tokens; Redis failure can delay revocation.
- Evidence: Session/BaseEntity have no version field; rotate performs find then session.rotate; role writes do not call session revocation; filter builds authorities from claims.
- Recommended fix: Atomic/optimistic-lock rotation with reuse detection, durable fail-closed revocation, and a subject authorization version checked on protected requests after role changes.
- Effort: L

### H-06 — Security/regression coverage is far below the required bar

- Category: Testing/assurance
- Location: src/test/java/com/authplatform/AuthplatformApplicationTests.java:1-16; pom.xml:16-52; no .github/workflows.
- What is wrong: One context test exists; no authorization matrix, tenant isolation, JWT negative, refresh reuse, rate-limit, signup race, query-count, Testcontainers, coverage, static-analysis, dependency-scan, or secret-scan workflow exists.
- Impact: IDOR, algorithm confusion, cross-tenant role assignment, races, and regressions can ship undetected.
- Evidence: rg --files src/test returns only AuthplatformApplicationTests.java; pom has no Testcontainers/JaCoCo/static-analysis dependency; no workflow file exists.
- Recommended fix: Add unit/slice/integration tests, Postgres+Redis Testcontainers, matrix/negative security tests, query-count assertions, JaCoCo threshold, and CI security gates.
- Effort: L

## Medium

### M-01 — Read-audit writes amplify page loads

- Category: Reliability/performance/audit
- Location: AuditService.java:21-60; SaService.java:62-103,156-167,199-257; V1__init.sql:10-13.
- What is wrong: SA analytics/list/detail/audit reads call REQUIRES_NEW and insert audit rows. Audit-log reads write on the request path. No retention/partition strategy or time/actor index is defined.
- Impact: Repeated View events increase write/connection pressure and audit noise. Live frequency is Unverified.
- Evidence: SA_VIEW_* calls occur in readOnly service methods; AuditService uses REQUIRES_NEW; audit_logs has no created_at/actor index.
- Recommended fix: Make read auditing sampled/off by default or separate low-value stream, add retention/partitioning/indexes, and measure request/DB amplification.
- Effort: M

### M-02 — Lists/dashboard use full entities, in-memory pagination, and N+1 queries

- Category: Data/performance
- Location: AppServiceImpl.java:89-97; AppController.java:73-79; SaService.java:62-80,88-103,156-167,199-223,268-295.
- What is wrong: App lists load all rows and skip/limit in memory; console user lists have no pagination; analytics counts per app; SA row mapping queries owner/count data repeatedly.
- Impact: Memory, query count, and latency grow with data size; large datasets can exhaust resources.
- Recommended fix: Page/projection queries with deterministic created_at,id sorting, aggregate counts, and query-count/EXPLAIN tests.
- Effort: M

### M-03 — Uniqueness races can become 500s and role uniqueness is case-sensitive in SQL

- Category: Data/API correctness
- Location: AccountAuthServiceImpl.java:60-67; AppUserAuthServiceImpl.java:73-79; SaService.java:106-112; RoleServiceImpl.java:72-77; V1__init.sql:4-8.
- What is wrong: Signup/SA/role creation check then insert. DB uniqueness exists, but DataIntegrityViolationException is not translated for those flows. Role SQL uniqueness is case-sensitive while service checks case-insensitively.
- Impact: Concurrent duplicates can return 500 instead of stable 409; role variants can violate intended semantics.
- Recommended fix: Translate integrity violations, canonicalize role names, and add concurrency tests.
- Effort: M

### M-04 — Error responses are not RFC 7807 and filters bypass the global contract

- Category: API contract
- Location: common/dto/ApiError.java:1-10; GlobalExceptionHandler.java:17-51; AppKeyAuthenticationFilter.java:34-49; JwtAuthenticationFilter.java:50-75.
- What is wrong: Errors use a custom {error:{...}} object, not application/problem+json ProblemDetail. Filters call sendError and can return container-specific bodies.
- Impact: SDK/frontend clients cannot rely on one stable contract.
- Recommended fix: Centralize JSON ProblemDetail output for filters and exceptions with stable codes/field errors; plan compatibility for the shape change.
- Effort: M

### M-05 — Origin/proxy/health behavior does not match production requirements

- Category: Operations/security
- Location: AppServiceImpl.java:165-171; AppOriginValidationFilter.java:18-35; application.yml:27-32; frontend/components/overview-page.tsx:17-20; frontend/components/audit-logs-page.tsx:48.
- What is wrong: Origins are regex/string checked, not parsed exact scheme/host/port values; localhost is not profile-gated. Native forwarded headers have no trusted-proxy config. Frontend health is hardcoded Healthy/Operational/Protected; IPv6 normalization is only display-side.
- Impact: Spoofed proxy headers can pollute IP/rate-limit data; production can accept local origins; the UI can report healthy dependencies when they are down. Actual proxy behavior is Unverified.
- Recommended fix: Trusted proxy/client-IP extraction, parsed exact origins, prod localhost rejection, real DB/Redis/readiness indicators, and data-driven UI health.
- Effort: M

### M-06 — App secret is stored safely but has no Stage 1 authentication consumer

- Category: API/security design
- Location: SecureRandomTokenGenerator.java:18-24; App.java:25-29,131-136; AppKeyAuthenticationFilter.java:34-45; repository-wide secret-key search.
- What is wrong: Secret generation is strong and storage is hashed, but the SDK filter accepts only the publishable key and no code consumes secretKeyHash.
- Impact: The secret credential is non-functional and can create false expectations about server-to-server protection.
- Recommended fix: Decide whether Stage 1 needs a separate server-secret path. If yes, add constant-time verification and never accept it from browser flows; if no, remove/rename it via a migration plan.
- Effort: M

## Low

### L-03 — Spring Boot 3.5.16 is at the end of its OSS release line; Java 21 is supported but the deployed build/license is unverified

- Category: Lifecycle/dependency management
- Location: pom.xml:7-14; Dockerfile:1-16.
- What is wrong: The project pins Spring Boot 3.5.16. Spring's June 2026 release announcement calls 3.5.16 the last OSS release of the 3.5 generation. Java 21 itself is not EOL in the vendor roadmap, but the exact deployed JDK build/license is not recorded.
- Impact: Future security fixes may require moving to Spring Boot 4.x or paid Spring support. An unpinned runtime image can drift between patch levels.
- Evidence: pom.xml pins 3.5.16 and Dockerfile uses moving `eclipse-temurin:21` tags. The official Spring release notice and Oracle Java roadmap are cited in the fix report.
- Recommended fix: Decide Spring Boot 4.x versus supported commercial 3.5 support, pin a patched Temurin image digest, and verify dependency CVEs in CI.
- Effort: M

### L-01 — Layering/configuration conventions are inconsistent

- Category: Design/maintainability
- Location: AppController.java:27-34; AppUserDetailsController.java:23-36; SecurityConfig.java:19-21.
- What is wrong: Controllers access repositories directly; services use raw status/action strings and @Value rather than typed properties/enums.
- Impact: Authorization and persistence rules are duplicated and harder to test.
- Recommended fix: Move query/authorization orchestration behind service interfaces and introduce typed configuration.
- Effort: M

### L-02 — Mutable entities have no optimistic-lock version

- Category: Data correctness
- Location: BaseEntity.java:11-31.
- What is wrong: BaseEntity has timestamps but no @Version.
- Impact: Concurrent administrative edits can silently overwrite each other.
- Recommended fix: Add a version column and conflict handling.
- Effort: M

## Nit

### N-01 — Release provenance and repeatable verification are weak

- Category: Release engineering
- Location: git status --short; README.md:9-15; frontend/package.json.
- What is wrong: Workspace has no commits, no CI workflow, and no npm lint/test scripts.
- Impact: Release provenance and automated gates are weak.
- Recommended fix: Establish release tracking and CI scripts/gates.
- Effort: S

## What is already good

- Argon2 is used for passwords: common/crypto/impl/Argon2PasswordHasher.java:8-17.
- 32-byte SecureRandom values are used for app and one-time tokens, with SHA-256-at-rest hashes: SecureRandomTokenGenerator.java:9-24; OneTimeTokenService.java:38-74.
- Normal app/detail DTOs expose only a four-character hint; full secret appears only in create/rotate response paths: AppServiceImpl.java:76-86,125-133; AppDtos.java:47-57,92-104. The reported short value is verified as a hint, not the secret.
- Refresh rotation tracks the previous hash and attempts reuse detection: SessionService.java:58-67,108-115.
- Lower-case unique email indexes exist for accounts and per-application users: V1__init.sql:4-8.
- Database audit UPDATE/DELETE protection exists: V4__immutable_audit_logs.sql:1-13.
- Flyway, ddl-auto=validate, and open-in-view=false are configured: application.yml:11-20.
- Owner/app predicates exist in app and role paths, though automated BOLA tests are absent.
- Frontend production build passed; source review found no localStorage/sessionStorage token storage and reviewed pages have loading/error states.

## Scorecard (1 poor — 5 production-ready)

| Category | Score | Evidence summary |
|---|---:|---|
| Security/authentication | 2 | Good password/token hashing; CSRF, JWT lifecycle, rate limits, enumeration, and stale claims remain. |
| Authorization/tenant isolation | 3 | Predicates exist; matrix/IDOR tests and service boundaries are missing. |
| API design/contracts | 2 | DTO validation exists; errors/pagination/contracts are incomplete. |
| Data/JPA | 2 | Flyway/constraints exist; no optimistic locking, race translation, projections, or query proof. |
| Reliability/performance | 2 | Async email exists; audit writes, N+1 paths, and Redis fallback are unsafe/untested. |
| Observability/operations | 1 | Request IDs exist; prod profiles, CI, proxy/Nginx, real health, and scans do not. |
| Frontend | 3 | Build passes and secrets are masked; direct browser API/BFF mismatch and hardcoded health remain. |
| Testing/release assurance | 1 | One context test; no matrix, integration, coverage, scans, or load test. |

## OWASP mapping

ASVS Level 2 gaps: V2 response uniformity/rate limiting, V3 session/token lifecycle, V4 access-control test coverage, V5 redirect validation, V7 errors, V8 secret lifecycle, V13 API security, and V14 configuration. Partial controls are Argon2, hashed one-time/refresh tokens, DTO validation, lower-case email uniqueness, request IDs, and the audit DB trigger.

API Security Top 10 (2023): API1/BOLA is source-mitigated in owner predicates but untested; API2 maps to B-01/B-02/H-01/H-04/H-05; API3 to mutable DTOs/direct controller repositories; API4 to H-01/M-01/M-02; API5 is manually implemented and untested; API6 maps to reset/signup/OTP limits; API7 SSRF is not evidenced; API8 maps to H-03/M-05; API9 maps to absent API/CI inventory; API10 is Unverified.

## Unverified items and exact verification methods

- EOL/CVEs: run ./mvnw versions:display-dependency-updates, OWASP dependency-check, npm audit --omit=dev, and verify Java/Spring vendor support dates on release day.
- Query plans: run representative requests against production-like PostgreSQL with EXPLAIN (ANALYZE, BUFFERS) and compare query counts.
- Redis failover: stop Redis during concurrent login/signup/reset/OTP tests across two backend instances and record statuses/keys/metrics.
- Proxy/AWS/TLS: deploy behind actual Nginx/ALB, send spoofed X-Forwarded-For, inspect audit/rate-limit IPs, and inspect security groups/RDS/IAM/TLS.
- Deployed secret leakage: run Gitleaks/TruffleHog on full history and image filesystem, then exercise app create/rotate/detail/list with log capture.
- Load: run a k6 script against production-like Postgres/Redis and record p50/p95/p99/error rate; no baseline exists yet.
