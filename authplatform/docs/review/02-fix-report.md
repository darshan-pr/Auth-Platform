# Production-readiness review — Phase 3 fix report

Review date: 2026-10-21 (Asia/Calcutta)

## Before/after

| Area | Before | After | Evidence |
|---|---|---|---|
| Cookie security | CSRF disabled; credentialed localhost wildcards; secure cookie default false | Cookie CSRF repository enabled for console/SA mutations, exact configured CORS origins, secure default true, production override disables docs | SecurityConfig.java; application.yml; application-prod.yml; frontend/lib/api.ts |
| JWT | New RSA key on every process start; no explicit algorithm/type/nbf checks | Configured key ring supports active plus retained kids, production fails without JWT_SIGNING_KEYS, parser pins RS256/JWT and validates exp/nbf/iat with bounded skew | JwtService.java; JwtServiceTest.java |
| Redirect token delivery | Arbitrary URL plus raw ?token= concatenation | HTTPS/local-dev URL validation rejects query/user-info/fragment/unsafe scheme | RedirectUrlValidator.java; RedirectUrlValidatorTest.java; AppServiceImpl.java; SaService.java |
| Rate limiting | Fixed Redis counter only on login/signup IP+path, local fallback | Redis atomic sliding-window script with separate login/signup/global settings and reset/resend/OTP coverage; Redis/auth lockout failures fail closed | RateLimitFilter.java; LoginAttemptService.java; application.yml |
| Session/roles | Concurrent refresh could race; role changes did not revoke app-user sessions | Pessimistic refresh-token row lock/reuse path; role assignment/permission/delete invalidates affected sessions; case-insensitive role index and duplicate translation added | SessionRepository.java; SessionService.java; RoleServiceImpl.java; V6 migration |
| API/data scale | Heap skip/limit and direct controller repository access; unbounded app-user list | Developer app and end-user list queries use bounded `PageRequest` and deterministic created_at/id sorting; app controller delegates to service | AppService.java; AppServiceImpl.java; AppController.java; repositories |
| App-user list compilation | Pagination mapping referenced a mapper that only existed in the former controller | Mapping now lives in `AppServiceImpl`, with a regression test covering the public DTO projection | AppServiceImpl.java; AppServiceImplTest.java |
| Application startup | Pessimistic-lock repository method was parsed as a derived query because `ForUpdate` was part of the method name | Explicit JPQL query preserves the `PESSIMISTIC_WRITE` lock and allows Spring Data repository initialization | SessionRepository.java; local startup verification |
| Audit noise | SA read requests always wrote REQUIRES_NEW audit rows | SA_VIEW reads are disabled by default and an audit query index was added; configuration can opt in | AuditService.java; application.yml; V7 migration |
| Ops UI/config | Hardcoded Healthy/Operational/Protected panel; no prod config/ignore file | UI reads Actuator health; prod override is fail-closed for docs and secure cookies; `.gitignore` added; Compose passes profile/key settings | frontend/components/overview-page.tsx; application-prod.yml; docker-compose.yml; .gitignore |
| Enumeration | Duplicate signup/status errors differed | Duplicate signup returns the same accepted-style response body/status family; password-valid unverified/SA/app-user states use generic invalid credentials | AccountAuthServiceImpl.java; AppUserAuthServiceImpl.java |

## Verification results

Passed:

- `./mvnw -q test` — exit 0.
- `./mvnw -q package` — exit 0.
- `./mvnw -q spotless:check` — exit 0 after applying the configured formatter.
- `./mvnw -q spring-boot:run -Dspring-boot.run.arguments='--server.port=18080 --spring.datasource.url=jdbc:postgresql://127.0.0.1:55432/authplatform'` — application context started, Flyway validated PostgreSQL, Tomcat reached port 18080, then the process was stopped gracefully.
- `npm run build` in `frontend/` — exit 0; Next.js 16.4.2 compiled and TypeScript completed.
- `npm audit --omit=dev --audit-level=high` — `found 0 vulnerabilities`.
- `./mvnw -q dependency:tree` — exit 0; resolved Spring Boot 3.5.16, Spring Framework 6.2.19, Spring Security 6.5.11, PostgreSQL JDBC 42.7.11, Nimbus 10.4, and other transitive versions.

Not clean or not run:

- OWASP Dependency-Check: failed before analysis because NVD returned `Invalid API Key, length of 0 too short`; this is Unverified, not clean. Run with an NVD API key and cache in CI.
- Secret scan: Gitleaks, TruffleHog, Trivy, Grype, Syft, and OSV-Scanner are unavailable in the environment. Run Gitleaks/TruffleHog against full history and the built image.
- k6: `load/authplatform.js` was added, but no production-like Postgres/Redis environment and test credentials were available. Baseline and final p50/p95/p99/error-rate numbers are Unverified and not reported as zero.
- Testcontainers, authorization matrix, query-count/N+1, IDOR, Redis failover, AWS/Nginx/TLS, and live append-only trigger tests were not run because no integration environment is available.

## Remaining risks

The project is improved but is not yet production-ready under the supplied definition of done. Remaining Blocker/High items are:

- H-01 remains partially open: the servlet IP window is sliding and account lockout is separate, but a full atomic per-account Redis window across all auth flows and a two-instance failover test are still needed.
- H-03 remains operationally open until the actual Nginx/ALB, AWS network/IAM, secret-manager, and production profile deployment are inspected. The new production profile only hardens application defaults.
- H-05 is partially open: role changes now revoke affected sessions, but already-issued JWT claims remain valid until expiry and the runtime Redis/DB revocation path needs an integration test.
- H-06 remains open: the required authorization matrix, tenant-isolation, token-negative, Testcontainers, coverage threshold, static/security CI, and query-count tests do not yet exist.
- M-04 remains open: the custom error wrapper and filter `sendError` paths have not been migrated to RFC 7807 because that is a client-visible contract change.
- M-06 remains a product decision: `secretKeyHash` is stored safely but no Stage 1 endpoint consumes the secret credential.
- L-02 remains open for general mutable entities: `Session` refresh rotation is row-locked, but `BaseEntity` still has no general `@Version` field.

## Needs my decision / migration plan

1. Error contract: approve a versioned ProblemDetail contract or retain the current `{error:{...}}` shape. If approved, add a compatibility adapter and document a deprecation window before removing the old shape.
2. Signup/status uniformity: duplicate signup and public login behavior changed to reduce enumeration. Confirm SDK/console clients accept the existing response shape with nullable IDs and generic messages; otherwise introduce `/api/v2` or a compatibility mode.
3. App secret: decide whether Stage 1 needs a server-to-server secret-authenticated surface. If yes, add a separate header and constant-time verification; if no, deprecate the unused secret fields through an additive migration.
4. JWT custody: provide the secret-manager owner and rotation procedure for `JWT_SIGNING_KEYS` entries (`kid|base64-private|base64-public`) and retain old public keys until the maximum access-token TTL has elapsed.
5. Spring lifecycle: Spring Boot 3.5.16 is the last OSS release of the 3.5 generation. Decide whether to move to Boot 4.x or use supported commercial maintenance. Java 21 remains an LTS line, but pin the Temurin image digest and deployed patch build.
6. V6 case-insensitive role index: before production migration, check for existing case-insensitive duplicates with `select app_id, lower(name), count(*) from roles group by app_id, lower(name) having count(*) > 1`; resolve duplicates before applying the unique index.

## Lifecycle evidence

Spring's official June 25, 2026 release notice says Spring Boot 3.5.16 is the last OSS release of the 3.5.x generation: [Spring Boot 3.5.16 release notice](https://spring.io/blog/2026/06/25/spring-boot-3-5-16-available-now/). Spring's system requirements page confirms Java 17–25 compatibility for 3.5.16: [Spring Boot 3.5 system requirements](https://docs.spring.io/spring-boot/3.5/system-requirements.html). Oracle's current roadmap lists Java 21 Premier Support through September 2028: [Oracle Java SE Support Roadmap](https://www.oracle.com/technetwork/java/javase/tech/eol-135779.html).
