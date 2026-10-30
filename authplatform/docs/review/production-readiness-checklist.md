# Production readiness checklist

| Category | Status | Evidence / next gate |
|---|---|---|
| Password/token cryptography | Partial | Argon2, hashed one-time/refresh/app secrets; JWT key custody/rotation integration test remains. |
| CSRF/CORS/cookies | Partial | CSRF and exact CORS implemented; verify actual origins/TLS/proxy deployment. |
| Rate limiting/lockout | Fail | Sliding-window code exists; full per-account semantics and Redis failover test remain. |
| Authorization/tenant isolation | Fail | Owner predicates exist; required role matrix/IDOR/Testcontainers tests absent. |
| API/error contract | Fail | DTO validation and request IDs pass; RFC 7807 migration is a decision. |
| PostgreSQL/JPA | Partial | Flyway/validate, constraints, role index, bounded lists; EXPLAIN/N+1/version tests absent. |
| Audit | Partial | DB append-only trigger and query index; live trigger/retention and read-audit volume verification absent. |
| Reliability/health | Partial | Async email and live Actuator health UI; AWS/Nginx/Redis/DB readiness deployment unverified. |
| Frontend | Partial | Build passes; direct browser API/BFF architecture and runtime auth flows need deployment verification. |
| CI/scanning | Fail | npm audit clean; OWASP scan needs NVD API key, secret scanner and CI workflow are absent. |
| Load/performance | Fail | k6 script added; baseline/final numbers not run. |
| Dependency lifecycle | Fail | Boot 3.5.16 is last OSS 3.5 release; migration/support decision required. |
