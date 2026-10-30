# authplatform — Stage 1 Implementation Plan

> A multi-tenant authentication platform (Clerk-style). Developers sign up, create apps, and get keys.
> Their end users sign up and log in to **those apps** through authplatform's APIs.
> This document is the single source of truth for building **Stage 1**. Follow it exactly.

---

## 0. Instructions for the AI building this

1. Read the whole document before writing code.
2. Build in the order of **Section 17 (Build Phases)**. After each phase the project must compile, tests must pass, and the app must start.
3. Generate **complete files**. No `// TODO`, no placeholders, no pseudo-code.
4. Obey **Section 11 (Java Coding Standards)** on every class. It is as important as the features.
5. Do **not** add anything listed in **Section 2 (Out of scope)**.
6. Use the latest stable versions of every dependency that are compatible with Spring Boot 3.x and Java 21.
7. If something is ambiguous, choose the more secure option and note the decision in `docs/DECISIONS.md`.

---

## 1. Overview

| Actor | Identity table | What they do |
|---|---|---|
| **Developer** | `accounts` | Signs up on the authplatform console, creates apps, gets keys |
| **End user** | `app_users` (scoped to one app) | Signs up / logs in to a customer's app through the SDK API |

Two completely separate identity pools. The same email can exist as a developer and as an end user of any number of apps; these are unrelated identities.

**Tenant = app.** Every `app_users` row carries an `app_id`. Every query on tenant data is scoped by `app_id`.

---

## 2. Scope

### In scope (Stage 1)

1. **Main app (console) auth**: sign up, verify email, resend verification, log in, refresh, log out, forgot password, reset password, get current account.
2. **App management**: create app (returns keys), list, get, update settings, rotate secret key.
3. **End-user auth for an app** (SDK API): sign up, verify email, resend verification, log in, refresh, log out, forgot password, reset password, get current user, JWKS endpoint.
4. **Security** (Section 8), **Redis rate limiting and lockout** (Section 9), **audit logging**, **emails** (verify / reset).
5. SA platform operations: analytics, account/app/SDK-user administration, credential rotation, and append-only audit-log access.
6. Local infra: Docker Compose (Postgres, Redis, Mailpit, Nginx, backend), OpenAPI docs, tests.

### Out of scope (do NOT build)

OAuth / OIDC provider and consent, role/permission **management** APIs (only the default role is seeded and put in the JWT), session list/revoke UI endpoints, MFA, social login, organizations, webhooks, Next.js frontend, JavaScript SDK, AWS deployment scripts.

---

## 3. Tech stack

| Concern | Choice |
|---|---|
| Language / runtime | Java 21 (virtual threads enabled), Maven |
| Framework | Spring Boot 3.x (web, security, data-jpa, validation, data-redis, actuator, mail) |
| Database | PostgreSQL 16 + Flyway migrations |
| Cache / rate limit | Redis 7 + Bucket4j (Lettuce module) |
| JWT | `nimbus-jose-jwt`, RS256, JWKS |
| Password hashing | Argon2id (`Argon2PasswordEncoder` + BouncyCastle) |
| Mapping | MapStruct |
| Boilerplate | Lombok (restricted, see 11.9) |
| Email | Spring Mail (SMTP) + Thymeleaf templates. Mailpit locally, SES SMTP in prod |
| Docs | springdoc-openapi |
| Tests | JUnit 5, Mockito, Testcontainers (Postgres + Redis), ArchUnit, Spring Security Test |
| Quality | Spotless (google-java-format), `-Xlint:all`, optional OWASP dependency-check |
| Edge | Nginx reverse proxy |

---

## 4. Architecture

**Modular monolith.** One deployable, strict module boundaries, communication through service interfaces and domain events.

```
Client ─► Nginx ─► Spring Boot ─► PostgreSQL
                       │
                       ├──► Redis (rate limit, lockout, caches, revoked-session list)
                       └──► SMTP (verification and reset emails)
```

### Request pipeline (filter order)

1. `RequestIdFilter`: reads or creates `X-Request-Id`, puts it in MDC.
2. `RateLimitFilter`: Redis-backed, policy chosen by path (Section 9).
3. `AppKeyAuthenticationFilter`: only `/api/v1/**`; resolves `X-authplatform-Key` to an app.
4. `AppOriginValidationFilter`: only `/api/v1/**`; enforces the app's allowed origins (Section 8.7).
5. `JwtAuthenticationFilter`: validates `Authorization: Bearer` tokens; also checks the revoked-session list in Redis.
6. Controller, then Service, then Repository.

### Routes

| Prefix | Audience | Auth |
|---|---|---|
| `/api/console/auth/**` | Developers (public endpoints) | none |
| `/api/console/**` | Developers | Bearer JWT (`aud=authplatform-console`) |
| `/api/sa/auth/**` | SA operators (bootstrap/login) | none |
| `/api/sa/**` | SA operators | Bearer JWT (`aud=authplatform-sa`, `role=SA`) |
| `/api/v1/**` | End users via SDK | `X-authplatform-Key` (+ Bearer where noted) |
| `/.well-known/jwks.json` | Anyone | none |
| `/actuator/health` | Infra | none (others locked down) |

---

## 5. Project structure

```
authplatform/
├── README.md
├── docs/DECISIONS.md
├── docker-compose.yml
├── infra/nginx/nginx.conf
└── backend/
    ├── pom.xml
    ├── Dockerfile
    └── src/
        ├── main/java/com/authplatform/
        │   ├── authplatformApplication.java
        │   │
        │   ├── common/
        │   │   ├── config/        SecurityConfig, CorsConfig, RedisConfig, AsyncConfig, ClockConfig,
        │   │   │                  OpenApiConfig
        │   │   │   └── properties/  JwtProperties, RateLimitProperties, SecurityProperties,
        │   │   │                    MailProperties, AppLimitsProperties   (@ConfigurationProperties records)
        │   │   ├── crypto/        PasswordHasher, TokenHasher, SecureTokenGenerator, KeyCipher   (interfaces)
        │   │   │   └── impl/      Argon2PasswordHasher, Sha256TokenHasher, SecureRandomTokenGenerator,
        │   │   │                  AesGcmKeyCipher
        │   │   ├── domain/        BaseEntity, AuthRealm, SubjectRef, ClientContext, EntityStatus
        │   │   ├── dto/           ApiError, PageResponse
        │   │   ├── exception/     ErrorCode, ApiException, GlobalExceptionHandler
        │   │   ├── filter/        RequestIdFilter
        │   │   └── validation/    StrongPassword, StrongPasswordValidator, ValidOrigin, ValidOriginValidator
        │   │
        │   ├── auth/
        │   │   ├── controller/    ConsoleAuthController, SdkAuthController, JwksController
        │   │   ├── service/       AccountAuthService, AppUserAuthService, SessionService,
        │   │   │                  AccessTokenService, OneTimeTokenService, LoginAttemptService,
        │   │   │                  SigningKeyService
        │   │   │   └── impl/      (one *Impl per interface)
        │   │   ├── security/      JwtAuthenticationFilter, AppKeyAuthenticationFilter,
        │   │   │                  AppOriginValidationFilter, AuthenticatedPrincipal
        │   │   ├── repository/    SessionRepository, EmailTokenRepository, SigningKeyRepository
        │   │   ├── entity/        Session, EmailToken, EmailTokenType, SigningKey
        │   │   ├── dto/           RegisterRequest, LoginRequest, TokenResponse, RefreshRequest,
        │   │   │                  VerifyEmailRequest, ForgotPasswordRequest, ResetPasswordRequest, MessageResponse
        │   │   └── mapper/
        │   │
        │   ├── user/
        │   │   ├── controller/    AccountController, AppUserController
        │   │   ├── service/       AccountService, AppUserService  (+ impl/)
        │   │   ├── repository/    AccountRepository, AppUserRepository
        │   │   ├── entity/        Account, AppUser, PlatformRole
        │   │   ├── dto/  mapper/
        │   │
        │   ├── app/
        │   │   ├── controller/    AppController
        │   │   ├── service/       AppService, AppCredentialService, AppLookupService  (+ impl/)
        │   │   ├── repository/    AppRepository
        │   │   ├── entity/        App
        │   │   ├── dto/           CreateAppRequest, UpdateAppRequest, AppResponse, AppCreatedResponse,
        │   │   │                  RotatedSecretResponse
        │   │   └── mapper/
        │   │
        │   ├── role/              (minimal in Stage 1)
        │   │   ├── service/       RoleService (+ impl/)
        │   │   ├── repository/    RoleRepository, AppUserRoleRepository
        │   │   └── entity/        Role, Permission, AppUserRole
        │   │
        │   ├── ratelimit/
        │   │   ├── RateLimitFilter, RateLimiter, RateLimitDecision, RateLimitPolicy,
        │   │   │   RateLimitPolicyResolver
        │   │   ├── key/           RateLimitKeyResolver (interface), IpKeyResolver, IpAndEmailKeyResolver,
        │   │   │                  AccountKeyResolver, AppKeyResolver
        │   │   └── impl/          RedisRateLimiter, InMemoryFallbackRateLimiter
        │   │
        │   ├── notification/
        │   │   ├── service/       EmailSender, EmailTemplateRenderer (+ impl/: SmtpEmailSender, ThymeleafEmailTemplateRenderer)
        │   │   └── listener/      NotificationEventListener
        │   │
        │   ├── audit/
        │   │   ├── service/       AuditService (+ impl/)
        │   │   ├── listener/      AuditEventListener
        │   │   ├── repository/    AuditLogRepository
        │   │   └── entity/        AuditLog
        │   │
        │   └── event/             domain event records (Section 12)
        │
        ├── main/resources/
        │   ├── application.yml, application-dev.yml, application-prod.yml
        │   ├── db/migration/      V1__init.sql, V2__indexes.sql
        │   └── templates/email/   verify-email.html, reset-password.html, password-changed.html
        │
        └── test/java/com/authplatform/
            ├── architecture/      ArchitectureRulesTest (ArchUnit)
            ├── support/           IntegrationTestBase (Testcontainers), CapturingEmailSender
            ├── auth/  app/  user/  ratelimit/   (unit + integration tests)
```

**Rule:** every service is an **interface in `service/`** and its **implementation in `service/impl/`**, in separate files.

---

## 6. Database (Flyway `V1__init.sql`)

Use UUID primary keys, `TIMESTAMPTZ` everywhere, no triggers (timestamps via JPA auditing).

```sql
CREATE TABLE accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           VARCHAR(320) NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    name            VARCHAR(120) NOT NULL,
    email_verified  BOOLEAN      NOT NULL DEFAULT FALSE,
    platform_role   VARCHAR(20)  NOT NULL DEFAULT 'USER',
    status          VARCHAR(20)  NOT NULL DEFAULT 'ACTIVE',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_accounts_email ON accounts (lower(email));

CREATE TABLE apps (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_account_id            UUID         NOT NULL REFERENCES accounts(id),
    name                        VARCHAR(100) NOT NULL,
    publishable_key             VARCHAR(80)  NOT NULL UNIQUE,
    secret_key_hash             CHAR(64)     NOT NULL,
    secret_key_hint             VARCHAR(12)  NOT NULL,
    allowed_origins             TEXT[]       NOT NULL DEFAULT '{}',
    verify_email_url            VARCHAR(500),
    reset_password_url          VARCHAR(500),
    require_email_verification  BOOLEAN      NOT NULL DEFAULT TRUE,
    status                      VARCHAR(20)  NOT NULL DEFAULT 'ACTIVE',
    created_at                  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX idx_apps_owner ON apps (owner_account_id);

CREATE TABLE app_users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id          UUID         NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    email           VARCHAR(320) NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    name            VARCHAR(120) NOT NULL,
    email_verified  BOOLEAN      NOT NULL DEFAULT FALSE,
    status          VARCHAR(20)  NOT NULL DEFAULT 'ACTIVE',
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_app_users_app_email ON app_users (app_id, lower(email));

CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id      UUID         NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    name        VARCHAR(60)  NOT NULL,
    description VARCHAR(255),
    is_default  BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (app_id, name)
);
CREATE UNIQUE INDEX uq_roles_one_default_per_app ON roles (app_id) WHERE is_default;

CREATE TABLE permissions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id      UUID         NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    key         VARCHAR(100) NOT NULL,
    description VARCHAR(255),
    UNIQUE (app_id, key)
);

CREATE TABLE role_permissions (
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE app_user_roles (
    app_user_id UUID        NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    role_id     UUID        NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (app_user_id, role_id)
);

CREATE TABLE sessions (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id             UUID REFERENCES accounts(id) ON DELETE CASCADE,
    app_user_id            UUID REFERENCES app_users(id) ON DELETE CASCADE,
    refresh_token_hash     CHAR(64)    NOT NULL UNIQUE,
    previous_refresh_hash  CHAR(64),
    ip_address             VARCHAR(45),
    user_agent             VARCHAR(255),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at             TIMESTAMPTZ NOT NULL,
    revoked_at             TIMESTAMPTZ,
    CONSTRAINT chk_sessions_one_subject CHECK (num_nonnulls(account_id, app_user_id) = 1)
);
CREATE INDEX idx_sessions_account  ON sessions (account_id)  WHERE revoked_at IS NULL;
CREATE INDEX idx_sessions_app_user ON sessions (app_user_id) WHERE revoked_at IS NULL;

CREATE TABLE email_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id   UUID REFERENCES accounts(id) ON DELETE CASCADE,
    app_user_id  UUID REFERENCES app_users(id) ON DELETE CASCADE,
    type         VARCHAR(20) NOT NULL,            -- VERIFY_EMAIL | RESET_PASSWORD
    token_hash   CHAR(64)    NOT NULL UNIQUE,
    expires_at   TIMESTAMPTZ NOT NULL,
    used_at      TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_email_tokens_one_subject CHECK (num_nonnulls(account_id, app_user_id) = 1)
);

CREATE TABLE audit_logs (
    id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    app_id             UUID,
    actor_account_id   UUID,
    actor_app_user_id  UUID,
    actor_type         VARCHAR(20) NOT NULL,       -- ACCOUNT | APP_USER | SYSTEM
    action             VARCHAR(60) NOT NULL,
    ip_address         VARCHAR(45),
    metadata           JSONB,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_app_time ON audit_logs (app_id, created_at DESC);

CREATE TABLE signing_keys (
    kid               VARCHAR(40) PRIMARY KEY,
    public_key_pem    TEXT        NOT NULL,
    private_key_enc   TEXT        NOT NULL,        -- AES-GCM encrypted
    active            BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Notes:
- Emails are normalized (`trim().toLowerCase()`) before every read and write.
- On first startup, if no active signing key exists, `SigningKeyService` generates an RSA 2048 key pair and stores the private key encrypted with `authplatform_KEY_ENCRYPTION_SECRET`.
- `permissions` and `role_permissions` exist now for forward compatibility. Stage 1 never writes to them.
- Never use `ddl-auto` other than `validate`.

---

## 7. API specification

**Conventions:** JSON only. Timestamps ISO-8601 UTC. IDs are UUIDs. Every error uses this shape:

```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Email or password is incorrect",
    "requestId": "7f3c9a...",
    "fieldErrors": [ { "field": "password", "message": "must be at least 10 characters" } ]
  }
}
```

(`fieldErrors` only for `VALIDATION_FAILED`.) All auth responses carry `Cache-Control: no-store`.

### 7.1 Console auth (developers), public

| Method | Path | Body | Success |
|---|---|---|---|
| POST | `/api/console/auth/signup` | `{name, email, password}` | `201 {id, email, emailVerified:false, message}` |
| POST | `/api/console/auth/verify-email` | `{token}` | `200 {emailVerified:true}` |
| POST | `/api/console/auth/resend-verification` | `{email}` | `202` generic message |
| POST | `/api/console/auth/login` | `{email, password}` | `200 {accessToken, expiresIn, account:{id,name,email,platformRole}}` + refresh cookie |
| POST | `/api/console/auth/refresh` | none (cookie) | `200 {accessToken, expiresIn}` + rotated cookie |
| POST | `/api/console/auth/logout` | none (cookie) | `204`, session revoked, cookie cleared |
| POST | `/api/console/auth/forgot-password` | `{email}` | `202 {message}` always the same |
| POST | `/api/console/auth/reset-password` | `{token, newPassword}` | `200 {message}`, all sessions revoked |

Refresh cookie: `HttpOnly; Secure; SameSite=Strict; Path=/api/console/auth; Max-Age=<refresh ttl>`.
`refresh` and `logout` also require header `X-Requested-With: authplatform-console` (CSRF defence in depth).

### 7.1a SA auth and platform operations

The first SA account is created only when the one-time bootstrap settings are enabled in `.env`. Public console signup always creates a regular developer account. After bootstrap, disable the settings. Additional SA accounts are created by an authenticated SA.

| Method | Path | Notes |
|---|---|---|
| POST | `/api/sa/auth/login` | `{email, password}`; returns an SA-audience access token and refresh cookie |
| POST | `/api/sa/auth/refresh` | rotates the SA refresh cookie |
| POST | `/api/sa/auth/logout` | revokes the SA session |
| GET | `/api/sa/analytics/overview` | platform totals and SDK-user counts per app |
| GET | `/api/sa/accounts` | all developer/SA accounts, paginated |
| POST | `/api/sa/accounts` | create another verified SA account |
| GET/PATCH | `/api/sa/accounts/{id}` | inspect or update an account; changes are audited |
| GET/PATCH | `/api/sa/apps/{id}` | inspect or update any app |
| POST | `/api/sa/apps/{id}/credentials/rotate` | rotate an app secret |
| GET | `/api/sa/users` | all SDK users, paginated |
| GET/PATCH | `/api/sa/apps/{appId}/users/{userId}` | inspect/update SDK users under any app |
| GET | `/api/sa/audit-logs` | append-only audit history, paginated |

### 7.2 Console (authenticated: `Authorization: Bearer <accessToken>`)

| Method | Path | Notes |
|---|---|---|
| GET | `/api/console/me` | current account |
| POST | `/api/console/apps` | create app. `{name, allowedOrigins[], verifyEmailUrl?, resetPasswordUrl?}` |
| GET | `/api/console/apps?page=&size=` | own apps only, paginated (`size` max 50) |
| GET | `/api/console/apps/{appId}` | 404 if not owner (never 403, to avoid leaking existence) |
| PATCH | `/api/console/apps/{appId}` | `name, allowedOrigins, verifyEmailUrl, resetPasswordUrl, requireEmailVerification, status (ACTIVE/SUSPENDED)` |
| POST | `/api/console/apps/{appId}/credentials/rotate` | new secret key, shown once |

**Create app, example**

```http
POST /api/console/apps
{ "name": "Acme Notes", "allowedOrigins": ["https://acmenotes.com", "http://localhost:3000"] }
```
```http
201 Created
{
  "id": "…uuid…",
  "name": "Acme Notes",
  "publishableKey": "pk_live_…",
  "secretKey": "sk_live_…",            // returned ONLY here and on rotation
  "allowedOrigins": ["https://acmenotes.com", "http://localhost:3000"],
  "requireEmailVerification": true,
  "defaultRole": { "id": "…uuid…", "name": "user" },
  "status": "ACTIVE",
  "createdAt": "2026-10-21T10:15:00Z"
}
```

Rules: max apps per account is `authplatform.limits.max-apps-per-account` (default 10, else `409 APP_LIMIT_REACHED`). Creation, in **one transaction**: insert app, generate keys, seed default role `user` (`is_default=true`), publish `AppCreated`. If URLs are omitted, emails fall back to `<first allowed origin>/verify-email?token=` and `/reset-password?token=`.

### 7.3 SDK auth (end users)

Every request needs header `X-authplatform-Key: pk_…`.

| Method | Path | Body | Success |
|---|---|---|---|
| POST | `/api/v1/auth/signup` | `{name, email, password}` | `201 {user:{id,email,emailVerified,roles}, verificationRequired}` |
| POST | `/api/v1/auth/verify-email` | `{token}` | `200 {emailVerified:true}` |
| POST | `/api/v1/auth/resend-verification` | `{email}` | `202` generic |
| POST | `/api/v1/auth/login` | `{email, password}` | `200 {accessToken, refreshToken, expiresIn, user:{id,name,email,roles,permissions}}` |
| POST | `/api/v1/auth/refresh` | `{refreshToken}` | `200 {accessToken, refreshToken, expiresIn}` (rotated) |
| POST | `/api/v1/auth/logout` | `{refreshToken}` | `204` |
| POST | `/api/v1/auth/forgot-password` | `{email}` | `202` generic |
| POST | `/api/v1/auth/reset-password` | `{token, newPassword}` | `200`, all of that user's sessions revoked |
| GET | `/api/v1/users/me` | Bearer token | `200` user with roles and permissions |
| GET | `/.well-known/jwks.json` | none | public keys (`Cache-Control: public, max-age=3600`) |

**Why the refresh token is in the body for the SDK (not a cookie):** the SDK runs on the customer's domain, so a cookie from authplatform's domain would be a blocked third-party cookie. The console is same-site behind Nginx, so it uses the safer httpOnly cookie. The SDK must keep the refresh token in memory or the customer's own secure storage. Document this trade-off in `docs/DECISIONS.md`.

If `requireEmailVerification=true`, login before verifying returns `403 EMAIL_NOT_VERIFIED`.

### 7.4 JWT design (RS256, header has `kid`)

| Claim | Console token | SDK token |
|---|---|---|
| `iss` | `authplatform.jwt.issuer` | same |
| `sub` | account id | app user id |
| `aud` | `authplatform-console` | app id |
| `sid` | session id | session id |
| `role` / `roles` | `role`: platform role | `roles`: array of role names |
| `permissions` | none | array (empty in Stage 1) |
| `jti`, `iat`, `exp` | yes | yes |

TTLs: access = 15 min, refresh = 30 days (configurable). A token issued for app A must be rejected by app B's checks (`aud`).

### 7.5 Error codes (single `ErrorCode` enum, with HTTP status and default message)

`VALIDATION_FAILED` 400 · `TOKEN_INVALID` 400 · `UNAUTHENTICATED` 401 · `INVALID_CREDENTIALS` 401 · `INVALID_KEY` 401 · `EMAIL_NOT_VERIFIED` 403 · `ACCESS_DENIED` 403 · `ORIGIN_NOT_ALLOWED` 403 · `APP_SUSPENDED` 403 · `USER_BLOCKED` 403 · `NOT_FOUND` 404 · `EMAIL_TAKEN` 409 · `APP_LIMIT_REACHED` 409 · `ACCOUNT_LOCKED` 423 · `RATE_LIMITED` 429 · `INTERNAL_ERROR` 500

---

## 8. Security requirements

1. **Passwords:** Argon2id via a `PasswordHasher` interface (swappable). Policy via `@StrongPassword`: 10 to 128 chars, at least one letter and one digit, must not contain the email local part. Never log or return password data.
2. **No user enumeration:** `forgot-password`, `resend-verification` always return the same response and take similar time (send email asynchronously). Login returns `INVALID_CREDENTIALS` for both "no user" and "wrong password"; when the user doesn't exist, still run a dummy hash comparison to equalize timing. (`signup` returns `EMAIL_TAKEN`, an accepted trade-off.)
3. **One-time tokens** (verify, reset): 32 random bytes, URL-safe Base64. Store only the SHA-256 hash. Single use (`used_at`). TTL: verify 24 h, reset 30 min. Issuing a new token of the same type invalidates older ones. Compare in constant time.
4. **API keys:** `pk_live_` + random for publishable; `sk_live_` + 32 random bytes for secret. Store only `SHA-256(secret)` plus a 4-char `secret_key_hint`. Show the secret once. Rotation invalidates the old one immediately.
5. **Sessions and refresh tokens:** random 256-bit opaque tokens, stored as SHA-256 hash. **Rotate on every refresh.** Keep `previous_refresh_hash`; if a previous (already used) token is presented again, treat it as theft: revoke the whole session and audit `REFRESH_TOKEN_REUSE_DETECTED`.
6. **Instant revocation:** on logout, password reset, or block, write each affected `sid` to Redis key `authplatform:revoked:sid:{sid}` with TTL = access-token TTL. `JwtAuthenticationFilter` rejects tokens whose `sid` is listed.
7. **CORS and origins:**
   - Console API: allow only configured frontend origins, with credentials.
   - `/api/v1/**`: browsers send a preflight without custom header values, so the app can't be identified there. Answer preflight with `Access-Control-Allow-Origin: <request origin>`, allow headers `Content-Type, Authorization, X-authplatform-Key`, and **no credentials** (the SDK flow uses no cookies). On the real request, `AppOriginValidationFilter` enforces the app's `allowed_origins` and returns `403 ORIGIN_NOT_ALLOWED`. If no `Origin` header is present (server-to-server), allow.
   - Origins must be exact `scheme://host[:port]`, lower-case, no trailing slash, `https` required except `localhost`. Max 20 per app. Validate with `@ValidOrigin`.
8. **Tenant isolation:** every repository method on tenant data takes `appId` (e.g. `findByAppIdAndEmailIgnoreCase`). Never call `findById` alone on `app_users`. An ArchUnit or integration test must prove user A of app 1 cannot be read through app 2's key.
9. **Suspended apps / blocked users:** `APP_SUSPENDED` / `USER_BLOCKED` on every SDK call.
10. **Transport and headers:** TLS terminates at Nginx. Spring uses `server.forward-headers-strategy=native`. Send `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and a restrictive `Content-Security-Policy` for API responses.
11. **Input handling:** Bean Validation on every request record, max body size 16 KB, reject unknown JSON properties, JPA parameterized queries only, never expose entities.
12. **Secrets:** only from environment variables, never committed. Required: `DB_URL, DB_USER, DB_PASSWORD, REDIS_URL, authplatform_KEY_ENCRYPTION_SECRET, SMTP_*`.
13. **Logging:** SLF4J parameterized, MDC `requestId`, never log passwords, tokens, keys, or full emails (mask: `a***@gmail.com`).
14. **Audit:** record `SIGNUP, EMAIL_VERIFIED, LOGIN_SUCCESS, LOGIN_FAILED, ACCOUNT_LOCKED, LOGOUT, PASSWORD_RESET_REQUESTED, PASSWORD_RESET_COMPLETED, APP_CREATED, APP_UPDATED, SECRET_KEY_ROTATED, REFRESH_TOKEN_REUSE_DETECTED` with IP and request id.

---

## 9. Rate limiting and lockout (Redis)

### Design

- `RateLimiter` interface: `RateLimitDecision tryConsume(RateLimitPolicy policy, String key)`.
- `RedisRateLimiter` implementation: **Bucket4j** with the Lettuce `ProxyManager`, token-bucket algorithm, state in Redis (works across multiple instances).
- `RateLimitFilter` asks `RateLimitPolicyResolver` which policies apply to the request, builds keys with `RateLimitKeyResolver` strategies, and rejects on the first denial.
- Redis key format: `authplatform:rl:{policy}:{key}`.
- On rejection: HTTP `429`, `ErrorCode.RATE_LIMITED`, headers `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`.
- **If Redis is down:** fall back to `InMemoryFallbackRateLimiter` with stricter limits and emit a `WARN` log plus a metric. Never silently disable limiting.
- All limits live in `RateLimitProperties` (YAML), never hard-coded.

### Policies (defaults)

| Policy | Applies to | Key | Limit |
|---|---|---|---|
| `LOGIN` | both login endpoints | IP + email | 5 / min |
| `LOGIN_IP` | both login endpoints | IP | 30 / min |
| `SIGNUP` | both signup endpoints | IP | 5 / 10 min |
| `PASSWORD_RESET_REQUEST` | forgot-password, resend-verification | email | 3 / 15 min |
| `PASSWORD_RESET_REQUEST_IP` | same | IP | 10 / hour |
| `TOKEN_CONSUME` | verify-email, reset-password | IP | 10 / min |
| `REFRESH` | refresh endpoints | IP | 30 / min |
| `APP_CREATE` | `POST /api/console/apps` | account id | 10 / hour |
| `CONSOLE_DEFAULT` | other console endpoints | account id | 120 / min |
| `SDK_APP_GLOBAL` | all `/api/v1/**` | publishable key | 1000 / min |

### Account lockout (separate from rate limiting)

`LoginAttemptService` (Redis):
- Key `authplatform:lock:fail:{realm}:{appIdOrConsole}:{email}` counts failures (TTL 15 min).
- After **5 failures** set `authplatform:lock:{…}` for **15 min** → `423 ACCOUNT_LOCKED`.
- Successful login clears the counter.
- Methods: `assertNotLocked`, `recordFailure`, `clearFailures`.

### Other Redis uses

- `authplatform:revoked:sid:{sid}` (Section 8.6).
- `authplatform:app:pk:{publishableKey}` caches the app lookup for 5 min (JSON). **Evict on update, suspend, rotate.**

---

## 10. Reusable building blocks (avoid duplication)

Console accounts and end users share almost all auth mechanics. Do **not** copy-paste between them. Build shared services keyed by a `SubjectRef`:

```java
public enum AuthRealm { CONSOLE, APP }

public record SubjectRef(AuthRealm realm, UUID subjectId, UUID appId) {}   // appId is null for CONSOLE
public record ClientContext(String ipAddress, String userAgent, String requestId) {}
```

| Shared service | Responsibility | Used by |
|---|---|---|
| `SessionService` | `startSession`, `rotateRefreshToken`, `revoke`, `revokeAll(subject)` | both auth services |
| `AccessTokenService` | `issueAccessToken(AccessTokenClaims)`, `parse`, JWKS | both |
| `OneTimeTokenService` | `issue(subject, type)`, `consume(rawToken, type)` | both |
| `LoginAttemptService` | lockout | both |
| `PasswordHasher`, `TokenHasher`, `SecureTokenGenerator` | crypto primitives | everywhere |
| `AuditService` | append audit rows | listeners |

`AccountAuthService` and `AppUserAuthService` stay thin orchestrators over these. Other shared code: `BaseEntity` (id, createdAt, updatedAt, auditing), `PageResponse<T>`, `ApiError`, `@StrongPassword`, injected `Clock` (never call `Instant.now()` directly).

---

## 11. Java coding standards (mandatory)

### 11.1 Layering

`Controller → Service (interface) → Repository`. Controllers are thin: bind and validate input, call **one** service method, return a DTO. No business logic in controllers, no repositories in controllers, no entities in API responses. Cross-module calls go **only** through service interfaces or domain events, never another module's repository or entity.

### 11.2 Interface + implementation, separate files

```
auth/service/AccountAuthService.java          // interface
auth/service/impl/AccountAuthServiceImpl.java // implementation
```

Callers depend on the interface only (Dependency Inversion). Every service has exactly one purpose.

### 11.3 Naming

- Classes: nouns (`SessionService`, `AppCredentialService`). DTOs: `XxxRequest` / `XxxResponse`. Mappers: `XxxMapper`. Events: past tense (`AppCreated`).
- Methods: verb + object, intention-revealing: `registerAccount`, `authenticate`, `issueAccessToken`, `rotateRefreshToken`, `revokeAllSessions`, `findActiveByEmail`, `assertNotLocked`.
- Booleans: `isEmailVerified`, `hasExpired`, `canLogin`. Repository checks: `existsBy…`.
- No abbreviations (`request`, not `req`), no `Manager`, `Helper`, `Processor`, `Utils` dumping-ground classes, no `Impl` without an interface.
- Constants in `UPPER_SNAKE_CASE`; replace magic numbers with named constants or properties.

### 11.4 SOLID, applied

- **S**: `AccountAuthServiceImpl` does not send email or write audit rows. It publishes events; listeners do that.
- **O**: new behavior by new implementations (`EmailSender`, `RateLimitKeyResolver`, `RateLimiter`), not by editing `if/else` chains.
- **L**: any implementation must honor the interface contract (e.g. fallback rate limiter returns the same `RateLimitDecision` semantics).
- **I**: small, focused interfaces (`PasswordHasher` has `hash` and `matches` only).
- **D**: constructor injection only, `private final` fields, `@RequiredArgsConstructor`. No field injection, no `@Autowired` on fields, no static service access.

### 11.5 Domain model (rich entities)

- Entities have **no public setters**. Behavior methods express intent: `account.markEmailVerified()`, `appUser.block()`, `session.revoke(now)`, `app.rotateSecret(hash, hint)`.
- Create via static factories: `Account.register(email, passwordHash, name)`.
- `protected` no-arg constructor for JPA, `equals/hashCode` based on id only, enums stored with `@Enumerated(EnumType.STRING)`.
- No `@Data`, no `@Setter`, no `@Builder` on entities.

### 11.6 DTOs and immutability

Java **records** for all DTOs, events, value objects, and `@ConfigurationProperties`. Return `Optional` (never `null`) from finders and empty collections (never `null`). Prefer `final` classes and `List.copyOf`.

### 11.7 Transactions and events

- `@Transactional` on service **implementation** methods; `readOnly = true` for reads.
- Publish domain events inside the transaction; handle them with `@TransactionalEventListener(phase = AFTER_COMMIT)` + `@Async` (bounded `ThreadPoolTaskExecutor`) so email/audit failures never roll back or slow the request.

### 11.8 Errors and validation

- One `ApiException(ErrorCode, …)`; `GlobalExceptionHandler` (`@RestControllerAdvice`) maps everything to `ApiError`. Never catch `Exception` to swallow it. Never leak stack traces.
- Validation with Bean Validation annotations on request records; reusable custom constraints (`@StrongPassword`, `@ValidOrigin`).

### 11.9 Lombok policy

Allowed: `@Getter`, `@RequiredArgsConstructor`, `@Slf4j`. Forbidden on entities: `@Data`, `@Setter`, `@Builder`, `@AllArgsConstructor`.

### 11.10 Design patterns to use deliberately

Strategy (`RateLimitKeyResolver`, `EmailSender`), Factory method (entity static factories, `AccessTokenClaims.forConsole/forApp`), Observer (Spring events), Facade (`AccountAuthService` over shared services), Template-free composition over inheritance.

### 11.11 Performance and optimization

- `spring.jpa.open-in-view=false`; HikariCP tuned (pool size from config); `hibernate.jdbc.batch_size` set.
- Avoid N+1: use `@EntityGraph` or DTO projections for list endpoints. **Never** an unbounded `findAll`; every list is paginated with an enforced max page size.
- Cache app lookup by publishable key in Redis (Section 9). Use the injected `Clock`. Enable virtual threads (`spring.threads.virtual.enabled=true`).
- Email sending always async. Index every foreign key and lookup column used in queries.

### 11.12 Code quality limits

Methods ≲ 20 lines, classes ≲ 300 lines, one level of nesting where possible, early returns over deep `if`, no commented-out code, Javadoc only on public interfaces (explain **why** and contracts, not the obvious). Spotless must pass.

### 11.13 Example style (follow this shape)

```java
// app/service/AppService.java
public interface AppService {
    AppCreatedResponse createApp(UUID ownerAccountId, CreateAppRequest request);
    PageResponse<AppResponse> listApps(UUID ownerAccountId, Pageable pageable);
    AppResponse getApp(UUID ownerAccountId, UUID appId);
    AppResponse updateApp(UUID ownerAccountId, UUID appId, UpdateAppRequest request);
    RotatedSecretResponse rotateSecretKey(UUID ownerAccountId, UUID appId);
}
```
```java
// app/service/impl/AppServiceImpl.java
@Service
@RequiredArgsConstructor
class AppServiceImpl implements AppService {

    private final AppRepository appRepository;
    private final AppCredentialService credentialService;
    private final RoleService roleService;
    private final AppMapper appMapper;
    private final AppLimitsProperties limits;
    private final ApplicationEventPublisher events;

    @Override
    @Transactional
    public AppCreatedResponse createApp(UUID ownerAccountId, CreateAppRequest request) {
        assertBelowAppLimit(ownerAccountId);
        GeneratedCredentials credentials = credentialService.generate();
        App app = appRepository.save(App.create(ownerAccountId, request.name(), request.allowedOrigins(), credentials));
        Role defaultRole = roleService.createDefaultRole(app.getId());
        events.publishEvent(new AppCreated(app.getId(), ownerAccountId));
        return appMapper.toCreatedResponse(app, credentials.rawSecretKey(), defaultRole);
    }

    private void assertBelowAppLimit(UUID ownerAccountId) {
        if (appRepository.countByOwnerAccountId(ownerAccountId) >= limits.maxAppsPerAccount()) {
            throw new ApiException(ErrorCode.APP_LIMIT_REACHED);
        }
    }
}
```
```java
// app/controller/AppController.java
@RestController
@RequestMapping("/api/console/apps")
@RequiredArgsConstructor
class AppController {
    private final AppService appService;

    @PostMapping
    ResponseEntity<AppCreatedResponse> create(@AuthenticationPrincipal AuthenticatedPrincipal principal,
                                              @Valid @RequestBody CreateAppRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(appService.createApp(principal.subjectId(), request));
    }
}
```

---

## 12. Domain events

Records in `event/`: `AccountRegistered`, `AppUserRegistered`, `EmailVerificationRequested`, `EmailVerified`, `PasswordResetRequested`, `PasswordResetCompleted`, `LoginSucceeded`, `LoginFailed`, `AccountLocked`, `LogoutCompleted`, `AppCreated`, `AppUpdated`, `SecretKeyRotated`, `RefreshTokenReuseDetected`.

- `NotificationEventListener` → sends verification / reset / password-changed emails (uses the **app's** name and URLs for end-user emails).
- `AuditEventListener` → writes `audit_logs`.

---

## 13. Configuration (`application.yml` keys)

```yaml
authplatform:
  jwt:
    issuer: https://auth.authplatform.local
    access-token-ttl: 15m
    refresh-token-ttl: 30d
  security:
    key-encryption-secret: ${authplatform_KEY_ENCRYPTION_SECRET}
    verify-token-ttl: 24h
    reset-token-ttl: 30m
    lockout: { max-failures: 5, window: 15m, duration: 15m }
    console-allowed-origins: [ "http://localhost:3000" ]
  limits:
    max-apps-per-account: 10
    max-origins-per-app: 20
  rate-limit:
    enabled: true
    policies:
      login:        { capacity: 5,    refill-period: 1m }
      signup:       { capacity: 5,    refill-period: 10m }
      # …one entry per policy in Section 9
spring:
  threads.virtual.enabled: true
  jpa: { open-in-view: false, hibernate.ddl-auto: validate }
  data.redis.url: ${REDIS_URL}
server.forward-headers-strategy: native
```

Profiles: `dev` (Mailpit, verbose logs), `prod` (JSON logs, SES SMTP).

---

## 14. Infrastructure (local)

`docker-compose.yml` services: `postgres:16`, `redis:7`, `mailpit` (SMTP 1025, UI 8025), `backend` (multi-stage Dockerfile, **non-root user**, healthcheck on `/actuator/health`), `nginx`.

Nginx: reverse proxy `/api` and `/.well-known` to backend; set `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Request-Id`; security headers; `client_max_body_size 16k`; gzip on; a coarse outer `limit_req_zone` per IP as a first line of defence (Redis limiter is the authoritative one); TLS config stubbed for prod.

Actuator: expose only `health`, `info`, `prometheus`; the latter two restricted to internal network.

---

## 15. Testing requirements

| Level | What |
|---|---|
| Unit (Mockito) | Every `*ServiceImpl`: happy path, each error code, edge cases (expired/used token, locked account, reused refresh token) |
| Integration (Testcontainers Postgres + Redis, `CapturingEmailSender`) | Full flows below, through real HTTP with `MockMvc`/`TestRestTemplate` |
| Architecture (ArchUnit) | Controllers don't touch repositories; modules don't access other modules' `repository`/`entity`; services end with `Service`, impls in `..service.impl..`; no field injection; no `java.util.logging` |
| Security | Cross-tenant access denied; JWT with wrong `aud` rejected; revoked `sid` rejected; secret key never returned after creation; rate limit returns 429 with `Retry-After` |

Target: ≥ 80% line coverage on service implementations.

**Required integration scenarios**

1. Console: signup → verify → login → refresh (old refresh token now fails and reuse revokes the session) → logout → forgot → reset → old sessions dead → login with new password.
2. Create app → response has keys once → list/get never include `secretKey` → rotate → old secret no longer valid.
3. SDK: signup on app A → verify → login → `GET /users/me` shows default role → same email signs up on app B independently → app A token rejected on app B.
4. Origin not allowed → 403; app suspended → 403; blocked user → 403.
5. 6th wrong login → 423; 11th request/min to login → 429.

---

## 16. Observability

Structured logs with `requestId`; Micrometer counters (`auth.login.success/failure`, `ratelimit.rejected`, `ratelimit.fallback.active`); health indicators for Postgres and Redis.

---

## 17. Build phases (do in order; each ends compiling + tests green)

| # | Phase | Deliverables | Done when |
|---|---|---|---|
| 0 | Skeleton | Maven project, Spotless, `docker-compose` (Postgres, Redis, Mailpit), Flyway `V1`, `common/` (properties, `BaseEntity`, errors, `RequestIdFilter`, crypto interfaces + impls), ArchUnit test | App boots, migration applies, `/actuator/health` UP |
| 1 | Console identity | `user` + `auth` modules: signup, verify, resend, login, refresh, logout, forgot, reset, `GET /me`; signing keys + JWKS; sessions, one-time tokens, JWT filter, revoked-sid list; email + audit listeners | Scenario 1 passes |
| 2 | Rate limiting and lockout | `ratelimit` module (Bucket4j/Redis + fallback), `LoginAttemptService`, headers, metrics | Scenario 5 passes |
| 3 | App management | `app` + minimal `role` modules; create/list/get/update/rotate; Redis app-lookup cache with eviction | Scenario 2 passes |
| 4 | End-user auth (SDK) | `AppKeyAuthenticationFilter`, `AppOriginValidationFilter`, `AppUserAuthService`, SDK controller, preflight handling, `users/me` | Scenarios 3 and 4 pass |
| 5 | Hardening and delivery | Security headers, OpenAPI polish, Nginx, Dockerfile, README run instructions, `docs/DECISIONS.md`, coverage check | All scenarios green, `docker compose up` works end to end |

---

## 18. Definition of done (Stage 1)

- [ ] All endpoints in Section 7 implemented and documented in OpenAPI
- [ ] All scenarios in Section 15 pass; coverage target met
- [ ] Every item in Section 8 (security) and Section 9 (rate limiting) implemented
- [ ] Section 11 standards honored (verified by ArchUnit + review): interface/impl separation, constructor injection, records for DTOs, no entity leakage, no duplicated auth logic between console and SDK
- [ ] No secrets in the repo; `.env.example` provided
- [ ] `docker compose up` starts the stack; a developer can sign up, create an app, and an end user can sign up and log in to that app, all via the documented APIs

---

## 19. Stage 2 (not now)

OAuth/OIDC consent layer, role and permission management APIs, session list/revoke endpoints for end users, Next.js console, JavaScript SDK, TOTP MFA, AWS deployment.
