# Production-readiness review — Phase 0 inventory

Review date: 2026-10-21 (Asia/Calcutta)

Scope: Stage 1 authentication, roles/permissions, application management, audit, and the sibling Next.js console. OAuth-provider features are intentionally out of scope.

## Evidence and verification boundary

This inventory is source/configuration based unless explicitly marked otherwise. The initial backend test command was attempted, but Maven could not acquire its local repository lock for Spring Boot 3.5.16 (`Could not open file channel ... spring-boot-starter-parent...3.5.16.lock`); the frontend production build completed successfully. Database `EXPLAIN ANALYZE`, Testcontainers, live Redis behavior, AWS/Nginx behavior, and runtime browser observations are not available from the repository alone and are marked Unverified below.

## Module/package map and dependency directions

The backend is a single Maven/Spring Boot application (`authplatform/pom.xml:1-64`) organized as a package-level modular monolith:

| Package/module | Responsibility | Observed dependencies |
|---|---|---|
| `auth` | Console, SA, SDK auth; sessions; JWT; one-time tokens; MFA; auth filters | `user`, `app`, `role`, `audit`, `notification`, `common` |
| `app` | Application entity, console app lifecycle, end-user administration | `role`, `user`, `audit`, `common` |
| `role` | Roles, permissions, assignments | `app` indirectly by controller authorization; `common` |
| `user` | Developer accounts and end users | `auth`, `app`, `role` in controllers |
| `sa` | Super-admin APIs, bootstrap, SA auth | `user`, `app`, `audit`, `auth`, `common` |
| `audit` | Audit entity, repository, append-only service | `common` |
| `ratelimit` | Servlet rate-limit filter | Redis/common configuration |
| `notification` | SMTP abstraction and sender | Spring Mail |
| `common` | Entities, crypto, security principal, filters, errors, config | Spring/JPA/security |

Dependency direction is not fully enforced by an architecture test. Repository access crosses package boundaries in controllers: `AppController` imports `AppRepository` and `AppUserRepository` (`src/main/java/com/authplatform/app/controller/AppController.java:10-12,27-34`), and `AppUserDetailsController` imports three repositories (`.../AppUserDetailsController.java:4-11,23-36`). Role controllers also import `AppRepository` for authorization (`.../RoleManagementController.java:27-33`).

Frontend: `frontend/app` contains route entry points; `frontend/components` contains client pages; `frontend/lib/api.ts` is the shared browser API client. The client calls the backend directly with `credentials: "include"` (`frontend/lib/api.ts:18-46`); no Next.js route-handler BFF is present in the source inventory.

## Endpoint inventory

Notation: `Anon` = anonymous; `Dev` = authenticated non-SA console account; `SA` = platform super-admin; `EU` = authenticated end user with matching publishable app key; `Key` = valid active publishable key; `AnyAuth` = authenticated JWT/cookie. Statuses are the implemented/expected statuses from controller return types and exception mapping. `RL` is based on `RateLimitFilter` (`src/main/java/com/authplatform/ratelimit/RateLimitFilter.java:35-62`); only POST paths ending in `/auth/login` or `/auth/signup` are covered by that filter. Audit events are source-observed; `—` means no audit call in the endpoint path.

### Authentication and public SDK surface

| Method/path | Caller | Request → response | Status | RL | Audit |
|---|---|---|---|---|---|
| POST `/api/console/auth/signup` | Anon | `RegisterRequest` → `SignupResponse` | 201; 400/409 | IP/path login bucket (implementation uses login settings) | `SIGNUP` |
| POST `/api/console/auth/verify-email` | Anon | `TokenRequest` → `VerifyResponse` | 200; 400 | None | `EMAIL_VERIFIED` |
| GET `/api/console/auth/verify-email?token=` | Anon | query token → HTML | 200; 400 | None | `EMAIL_VERIFIED` |
| POST `/api/console/auth/resend-verification` | Anon | `ForgotPasswordRequest` → `MessageResponse` | 202; 400 | None | — |
| POST `/api/console/auth/login` | Anon | `LoginRequest` → `ConsoleLoginResult` and cookies | 200/202; 401/403/429 | IP/path bucket; account lockout separately | `LOGIN_FAILED` / success audit occurs after OTP |
| POST `/api/console/auth/login/otp` | Anon | `OtpVerify` → `ConsoleLoginResult` and cookies | 200; 401/429 | None in filter | `LOGIN_SUCCESS` |
| POST `/api/console/auth/refresh` | Console cookie + header | cookie → `ConsoleRefreshResult` and cookies | 200; 401/403 | None | refresh audit is not consistently IP-attributed |
| POST `/api/console/auth/logout` | Console cookie + header | cookie → empty | 204; 403 | None | — |
| POST `/api/console/auth/forgot-password` | Anon | `ForgotPasswordRequest` → `MessageResponse` | 202; 400 | None | `PASSWORD_RESET_REQUESTED` only for existing account |
| POST `/api/console/auth/reset-password` | Anon | `ResetPasswordRequest` → `MessageResponse` | 200; 400 | None | `PASSWORD_RESET_COMPLETED` |
| POST `/api/v1/auth/signup` | Key/Anon at HTTP layer | `RegisterRequest` → `UserSummary` | 201; 401/403/400/409 | IP/path bucket | `SIGNUP` |
| POST `/api/v1/auth/verify-email` | Key | `TokenRequest` → `VerifyResponse` | 200; 400 | None | `EMAIL_VERIFIED` |
| POST `/api/v1/auth/resend-verification` | Key | `ForgotPasswordRequest` → `MessageResponse` | 202; 400 | None | — |
| POST `/api/v1/auth/login` | Key | `LoginRequest` → `LoginResponse` | 200/202; 401/403/429 | IP/path bucket; account lockout separately | `LOGIN_FAILED` / `LOGIN_SUCCESS` |
| POST `/api/v1/auth/login/otp` | Key | `OtpVerify` → `LoginResponse` | 200; 401 | None in filter | `LOGIN_SUCCESS` |
| POST `/api/v1/auth/refresh` | Key | `RefreshRequest` → `LoginResponse` | 200; 401 | None | `TOKEN_REFRESHED` if emitted by service |
| POST `/api/v1/auth/logout` | Key | `RefreshRequest` → empty | 204; 400 | None | — |
| POST `/api/v1/auth/forgot-password` | Key | `ForgotPasswordRequest` → `MessageResponse` | 202; 400 | None | — |
| POST `/api/v1/auth/reset-password` | Key | `ResetPasswordRequest` → `MessageResponse` | 200; 400 | None | `PASSWORD_RESET_COMPLETED` |
| GET `/api/v1/auth/mfa/status` | EU + Key | no body → `MfaDtos.Status` | 200; 401 | None | — |
| GET `/api/v1/users/me` | EU + Key | no body → `UserSummary` | 200; 401 | None | — |
| GET `/.well-known/jwks.json` | Anon | no body → JWK set | 200 | None | — |

### Developer console and application management

| Method/path | Caller | Request → response | Status | RL | Audit |
|---|---|---|---|---|---|
| GET `/api/console/me` | Dev | no body → `AccountSummary` | 200; 401 | None | — |
| POST `/api/console/apps` | Dev | `CreateAppRequest` → `AppCreatedResponse` (secret once) | 201; 400/409 | None | `APP_CREATED` |
| GET `/api/console/apps?page&size` | Dev | query page → `List<AppResponse>` | 200; 401 | None | — |
| GET `/api/console/apps/{id}` | Owner Dev | no body → `AppResponse` | 200; 401/404 | None | — |
| PATCH `/api/console/apps/{id}` | Owner Dev | `UpdateAppRequest` → `AppResponse` | 200; 400/401/404 | None | `APP_UPDATED` |
| POST `/api/console/apps/{id}/credentials/rotate` | Owner Dev | no body → `RotatedSecretResponse` (secret once) | 200; 401/404 | None | `SECRET_KEY_ROTATED` |
| GET `/api/console/apps/{id}/users` | Owner Dev | no body → `List<AppUserView>` | 200; 401/404 | None | — |
| PATCH `/api/console/apps/{appId}/users/{userId}` | Owner Dev | `UpdateAppUserRequest` → `AppUserView` | 200; 400/401/404 | None | `APP_USER_UPDATED` |
| GET `/api/console/apps/{appId}/users/{userId}/details` | Owner Dev | no body → `AppUserDetailsView` | 200; 401/403/404 | None | — |
| GET `/api/console/apps/{appId}/roles` | Owner Dev | no body → `List<RoleView>` | 200; 401/403/404 | None | — |
| POST `/api/console/apps/{appId}/roles` | Owner Dev | `CreateRoleRequest` → `RoleView` | 200; 400/401/403 | None | — |
| PATCH `/api/console/apps/{appId}/roles/{roleId}` | Owner Dev | `UpdateRoleRequest` → `RoleView` | 200; 400/401/403/404 | None | — |
| DELETE `/api/console/apps/{appId}/roles/{roleId}` | Owner Dev | no body → empty | 204; 401/403/404 | None | — |
| GET `/api/console/apps/{appId}/permissions` | Owner Dev | no body → `List<PermissionView>` | 200; 401/403 | None | — |
| POST `/api/console/apps/{appId}/permissions` | Owner Dev | `CreatePermissionRequest` → `PermissionView` | 200; 400/401/403 | None | — |
| POST `/api/console/apps/{appId}/roles/{roleId}/permissions` | Owner Dev | `AssignPermissionRequest` → empty | 204; 400/401/403/404 | None | — |
| DELETE `/api/console/apps/{appId}/roles/{roleId}/permissions/{permissionId}` | Owner Dev | no body → empty | 204; 401/403/404 | None | — |
| GET `/api/console/apps/{appId}/users/{userId}/roles` | Owner Dev | no body → `UserRolesView` | 200; 401/403/404 | None | — |
| POST `/api/console/apps/{appId}/users/{userId}/roles/{roleId}` | Owner Dev | no body → empty | 204; 401/403/404 | None | — |
| DELETE `/api/console/apps/{appId}/users/{userId}/roles/{roleId}` | Owner Dev | no body → empty | 204; 401/403/404 | None | — |
| GET `/api/console/mfa/status` | Dev | no body → `MfaDtos.Status` | 200; 401 | None | — |

### SA console

| Method/path | Caller | Request → response | Status | RL | Audit |
|---|---|---|---|---|---|
| POST `/api/sa/auth/login` | Anon | `SaDtos.LoginRequest` → `SaDtos.LoginResponse` | 200/202; 401/403/429 | IP/path bucket; account lockout separately | `SA_LOGIN_FAILED` / success after OTP |
| POST `/api/sa/auth/login/otp` | Anon | `OtpVerify` → `SaDtos.LoginResponse` and cookies | 200; 401 | None in filter | `SA_LOGIN_SUCCESS` |
| POST `/api/sa/auth/refresh` | SA cookie + header | cookie → `SaDtos.LoginResponse` and cookies | 200; 401/403 | None | `SA_TOKEN_REFRESHED` |
| POST `/api/sa/auth/logout` | SA cookie + header | cookie → empty | 204; 403 | None | — |
| GET `/api/sa/me` | SA | no body → `AccountView` | 200; 401/403 | None | — |
| GET `/api/sa/mfa/status` | SA | no body → `MfaDtos.Status` | 200; 401/403 | None | — |
| GET `/api/sa/analytics/overview` | SA | no body → `AnalyticsOverview` | 200; 401/403 | None | `SA_VIEW_ANALYTICS` |
| GET `/api/sa/accounts?page&size` | SA | query page → `PageResponse<AccountView>` | 200; 401/403 | None | `SA_VIEW_ACCOUNTS` |
| POST `/api/sa/accounts` | SA | `CreateSaRequest` → `AccountView` | 200; 400/401/403/409 | None | `SA_ACCOUNT_CREATED` |
| GET `/api/sa/accounts/{id}` | SA | no body → `AccountDetails` | 200; 401/403/404 | None | `SA_VIEW_ACCOUNT` |
| PATCH `/api/sa/accounts/{id}` | SA | `UpdateAccountRequest` → `AccountView` | 200; 400/401/403/404 | None | `SA_ACCOUNT_UPDATED` |
| GET `/api/sa/apps?page&size` | SA | query page → `PageResponse<AppView>` | 200; 401/403 | None | `SA_VIEW_APPS` |
| GET `/api/sa/apps/{id}` | SA | no body → `AppView` | 200; 401/403/404 | None | `SA_VIEW_APP` |
| PATCH `/api/sa/apps/{id}` | SA | `UpdateAppRequest` → `AppView` | 200; 400/401/403/404 | None | `SA_APP_UPDATED` |
| POST `/api/sa/apps/{id}/credentials/rotate` | SA | no body → `RotatedSecretResponse` | 200; 401/403/404 | None | `SA_APP_SECRET_ROTATED` |
| GET `/api/sa/users?page&size` | SA | query page → `PageResponse<AppUserView>` | 200; 401/403 | None | `SA_VIEW_USERS` |
| GET `/api/sa/apps/{appId}/users?page&size` | SA | query page → `PageResponse<AppUserView>` | 200; 401/403/404 | None | `SA_VIEW_APP_USERS` |
| PATCH `/api/sa/apps/{appId}/users/{userId}` | SA | `UpdateAppUserRequest` → `AppUserView` | 200; 400/401/403/404 | None | `SA_APP_USER_UPDATED` |
| GET `/api/sa/audit-logs?page&size` | SA | query page → `PageResponse<AuditLogView>` | 200; 401/403 | None | `SA_VIEW_AUDIT_LOGS` |
| GET `/api/sa/apps/{appId}/users/{userId}/details` | SA | no body → `AppUserDetailsView` | 200; 401/403/404 | None | — |
| GET `/api/sa/apps/{appId}/roles` plus role/permission endpoints above | SA | same role DTOs | 200/204; 401/403/404 | None | — |

Endpoint mapping evidence: controller annotations under `src/main/java/com/authplatform/**/controller`; DTO definitions under `src/main/java/com/authplatform/{auth,app,role,sa}/dto`; security matcher policy is `src/main/java/com/authplatform/common/config/SecurityConfig.java:32-61`.

## Entity/ER summary, constraints, and indexes

`V1__init.sql:4-13` defines:

```text
accounts 1 ──< apps 1 ──< app_users
apps 1 ──< roles >──< permissions (role_permissions)
app_users >──< roles (app_user_roles)
accounts/app_users 1 ──< sessions
accounts/app_users 1 ──< email_tokens
audit_logs records optional account/app-user/app subject IDs
signing_keys stores public/private signing material
```

Constraints observed:

- UUID primary keys on accounts/apps/app_users/roles/permissions/sessions/email_tokens; identity primary key on audit logs; `signing_keys.kid` primary key.
- Foreign keys from apps to accounts, app_users to apps, roles/permissions to apps, join tables to their parents, sessions/email_tokens to their subject tables. App and role/permission/user joins use `ON DELETE CASCADE` where declared.
- Lowercase unique index on `accounts.email`; composite lower-expression unique index on `(app_id, email)` for app users; unique app publishable key and secret/refresh/token hashes; unique role name `(app_id,name)` is case-sensitive; one default role partial unique index per app; composite PKs on join tables; one-subject check constraints on sessions and email tokens.
- Audit append-only trigger is database-enforced by `V4__immutable_audit_logs.sql:1-13`.
- Indexes: `idx_apps_owner`, partial session indexes for active sessions, and unique indexes above. No explicit indexes are present for audit `(created_at, actor, action)`, email-token expiry, or role/permission app lookups beyond uniqueness indexes.

JPA entity mapping uses `Instant` and PostgreSQL `TIMESTAMPTZ` schema columns (`V1__init.sql:4-13`, `.../BaseEntity.java:1-44`). Query plans and N+1 behavior are Unverified; verify with PostgreSQL `EXPLAIN (ANALYZE, BUFFERS)` on list/detail queries and Hibernate SQL/query-count tests against Testcontainers.

## Configuration/profile summary

The base configuration is `src/main/resources/application.yml:1-50`; a production override was added during this review at `src/main/resources/application-prod.yml:1-18`. There is no dedicated dev override. The base file imports an optional local `.env`, requires DB/Redis/SMTP/JWT/rate-limit values from environment, and sets `hibernate.ddl-auto=validate`, Flyway enabled, and `open-in-view=false` (`application.yml:1-20`).

Development defaults and surfaces: Docker Compose exposes Postgres `55432`, Redis `6379`, Mailpit SMTP/UI, and backend `8080` (`docker-compose.yml:1-61`); Swagger and Actuator health/docs are reachable according to `README.md:9-15` and `application.yml:30-32`. Production-specific settings such as secure cookies, profile-gated demo data, TLS/Nginx, secret-manager imports, pool/query timeouts, and trusted-proxy configuration are not represented. Whether deployment infrastructure supplies compensating controls is Unverified.

## Dependency list with versions

Directly declared in `authplatform/pom.xml:7-52`:

| Dependency/tool | Version |
|---|---:|
| Spring Boot parent / starters | 3.5.16 parent-managed (starters inherit managed versions); Spring's June 2026 release announcement identifies 3.5.16 as the last OSS release of the 3.5 generation, so support/migration must be decided |
| Java source/target | 21 |
| Nimbus JOSE JWT | 10.4 |
| springdoc OpenAPI WebMVC UI | 2.8.13 |
| Bouncy Castle `bcprov-jdk18on` | 1.82 |
| Flyway core + PostgreSQL database module | parent-managed |
| PostgreSQL JDBC | parent-managed |
| Lombok | parent-managed, optional |
| Spotless Maven plugin | 3.10.4; Google Java Format is configured |
| Spring Boot test/security test | parent-managed, test scope |

Frontend package versions from `frontend/package.json`: Next.js 16.4.2 (confirmed by `npm run build` output), React 19.1.0, React DOM 19.1.0, TypeScript 5.x, and ESLint 9.x as listed in the package manifest. Exact transitive dependency/CVE status requires a successful `mvn dependency:tree`, `npm audit --omit=dev`, and an approved vulnerability scanner run; those results are Phase 3 items.

Runtime lifecycle: Java 21 is an LTS line with Oracle's current roadmap listing Premier Support through September 2028; the Docker image uses Eclipse Temurin 21. Oracle's October 2026 update licensing change for Oracle JDK 21 does not apply to Temurin, but the exact deployed JDK build/license remains Unverified.

