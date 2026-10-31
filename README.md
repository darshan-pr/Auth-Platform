# Auth Platform

A multi-tenant authentication platform. Developers register applications in a console and get publishable keys and a drop-in SDK. End users then sign up, sign in, verify email, reset passwords and manage sessions through the platform's API, with RS256 JWTs, rotating refresh tokens, email one-time-password (OTP) MFA, role-based permissions and an audit log.

- **Backend:** Spring Boot 3.5, Java 21, PostgreSQL 16 (Flyway), Redis-compatible store (rate limits, lockout, OTPs, session revocation)
- **Console:** Next.js 16 app for developers (`/console/*`) and platform administrators (`/sa/*`)
- **SDK:** `@authplatform/auth-core`, `@authplatform/auth-nextjs`, `@authplatform/auth-react` (npm install: **coming soon**)
- **Production:** AWS, single Availability Zone in `eu-north-1`, provisioned with Terraform and deployed by GitHub Actions at **https://auth.darshan-pr.tech**

## Contents

1. [Architecture](#1-architecture)
2. [Production infrastructure (AWS)](#2-production-infrastructure-aws)
3. [CI/CD](#3-cicd)
4. [Capacity and availability](#4-capacity-and-availability)
5. [Low-level design](#5-low-level-design)
6. [Repository layout](#6-repository-layout)
7. [Run it locally](#7-run-it-locally)
8. [Configuration](#8-configuration)
9. [Known limitations](#9-known-limitations)

---

## 1. Architecture

Three kinds of people use the platform:

| Actor | What they do | Where |
|---|---|---|
| **Platform admin (SA)** | Operates the platform: all accounts, applications, end users, audit logs | Console `/sa/login` |
| **Developer** | Creates applications, keys, roles and permissions, manages their end users | Console `/login` |
| **End user** | Signs in to a developer's own application | Developer's app using the SDK |

### System context

```mermaid
flowchart TB
    dev["Developer<br/>creates apps, roles, keys"]
    sa["Platform admin (SA)<br/>operates the platform"]
    eu["End user<br/>signs in to a customer app"]

    subgraph customer["Customer application (Next.js)"]
        ui["React UI<br/>@authplatform/auth-react"]
        bff["BFF route /api/auth/*<br/>@authplatform/auth-nextjs<br/>tokens stay in HttpOnly cookies"]
        ui -->|"same origin"| bff
    end

    subgraph platform["Auth Platform - https://auth.darshan-pr.tech"]
        console["Console<br/>Next.js 16, port 3000"]
        api["Backend API<br/>Spring Boot 3.5 / Java 21, port 8080"]
    end

    pg[("PostgreSQL 16<br/>system of record")]
    redis[("Redis-compatible store<br/>rate limits, OTPs, revocations")]
    smtp["SMTP provider<br/>OTP and verification emails"]

    dev --> console
    sa --> console
    eu --> ui
    console -->|"/api/console/* and /api/sa/*<br/>HttpOnly cookies + CSRF"| api
    bff -->|"/api/v1/*<br/>X-authplatform-Key header"| api
    api --> pg
    api --> redis
    api --> smtp
```

Key design decisions:

- **The browser never sees a token.** In a customer application, the SDK's Next.js BFF holds the access and refresh tokens in HttpOnly cookies and forwards them to the backend as bearer tokens. The console uses backend-set HttpOnly cookies the same way.
- **One public hostname.** The load balancer sends `/api/*` and `/.well-known/*` to the backend and everything else to the console, so cookies and CORS stay same-origin.
- **Stateless backend.** All state lives in PostgreSQL and Redis, so the API can be scaled horizontally.

### Sign-in with MFA (SDK end user)

```mermaid
sequenceDiagram
    autonumber
    actor U as End user
    participant B as Browser (React SDK)
    participant N as Next.js BFF
    participant A as Backend API
    participant R as Redis
    participant D as PostgreSQL
    participant M as SMTP

    U->>B: email and password
    B->>N: POST /api/auth/login with CSRF header
    N->>A: POST /api/v1/auth/login with X-authplatform-Key
    A->>R: rate limit and lockout check
    A->>D: load user and verify Argon2 hash
    alt application requires MFA
        A->>R: store OTP for 5 minutes
        A->>M: email 6-digit code
        A-->>N: 202 challengeId, no profile, no tokens
        N-->>B: otpRequired
        U->>B: enter code
        B->>N: POST /api/auth/login/otp
        N->>A: POST /api/v1/auth/login/otp
        A->>R: verify code and count attempts
    end
    A->>D: create session with hashed refresh token
    A-->>N: access JWT and refresh token
    N-->>B: Set-Cookie HttpOnly access and refresh
```

---

## 2. Production infrastructure (AWS)

Everything runs in one Availability Zone (`eu-north-1a`). An empty second subnet pair in `eu-north-1b` exists only because an Application Load Balancer and an RDS subnet group each require two AZs. **No compute runs in `eu-north-1b`.** Production runs without Docker: the two applications are `systemd` services on the instance.

```mermaid
flowchart TB
    users(["Users and customer app servers"])
    dns["DNS CNAME<br/>auth.darshan-pr.tech<br/>(at the domain registrar)"]
    smtp["SMTP provider<br/>(Gmail)"]
    users --> dns

    subgraph aws["AWS account - region eu-north-1 (Stockholm)"]
        subgraph support["Supporting services - not in the request path"]
            direction LR
            acm["ACM<br/>TLS certificate"]
            ssm["SSM Parameter Store<br/>secrets and git_ref"]
            iam["IAM<br/>instance profile and<br/>GitHub OIDC deploy role"]
            budget["AWS Budgets<br/>cost alert"]
        end

        subgraph vpc["VPC 10.20.0.0/16"]
            alb["Application Load Balancer<br/>listeners 80 and 443<br/>spans both public subnets<br/>via the Internet Gateway"]

            subgraph azb["AZ eu-north-1b - ALB and RDS requirement only, no workloads"]
                direction LR
                pubb["Public subnet<br/>10.20.1.0/24"]
                datab["Data subnet<br/>10.20.11.0/24"]
            end

            subgraph aza["AZ eu-north-1a - all workloads"]
                subgraph puba["Public subnet 10.20.0.0/24"]
                    subgraph ec2["EC2 t4g.small - Amazon Linux 2023 arm64<br/>2 vCPU, 2 GB RAM, 2 GB swap<br/>security group: ALB traffic only, no SSH"]
                        direction LR
                        fe["authplatform-frontend<br/>Next.js console :3000"]
                        be["authplatform-backend<br/>Spring Boot API :8080<br/>JVM heap 256 to 640 MB"]
                    end
                end
                subgraph dataa["Private data subnet 10.20.10.0/24 - no internet route"]
                    direction LR
                    rds[("RDS PostgreSQL 16<br/>db.t4g.micro, 20 GB gp3<br/>encrypted, TLS enforced<br/>7-day backups")]
                    mdb[("MemoryDB for Valkey 7.3<br/>db.t4g.small, 1 node<br/>TLS and ACL user")]
                end
            end
        end
    end

    dns --> alb
    alb -->|"default route to :3000"| fe
    alb -->|"/api/* and /.well-known/* to :8080"| be
    be -->|"5432 TLS verify-full"| rds
    be -->|"6379 TLS"| mdb
    be -->|"587 STARTTLS"| smtp
```

### Traffic routing at the load balancer

```mermaid
flowchart LR
    c(["Client"]) -->|"HTTP :80"| l80["Listener :80"]
    l80 -->|"301 redirect"| l443
    c -->|"HTTPS :443"| l443["Listener :443<br/>ACM cert, TLS 1.3 / 1.2 policy"]
    l443 -->|"path /api/* or /.well-known/*<br/>rule priority 10"| tgb["Target group backend :8080<br/>health: /actuator/health"]
    l443 -->|"default action"| tgf["Target group frontend :3000<br/>health: /"]
    tgb --> ec2["EC2 instance"]
    tgf --> ec2
```

### Network and security groups

Security groups reference each other, so only the intended hop can connect:

| Security group | Inbound | Outbound |
|---|---|---|
| `alb` | 80, 443 from the internet | 3000 and 8080 to `app` |
| `app` | 3000, 8080 from `alb` only | 443, 80, 22 (git over SSH), 587 (SMTP) to the internet, 5432 to `rds`, 6379 to `memorydb` |
| `rds` | 5432 from `app` only | none |
| `memorydb` | 6379 from `app` only | none |

The instance has a public IPv4 address (to avoid the cost of a NAT gateway) but accepts no traffic from the internet. There is no SSH; use **SSM Session Manager**.

### Secrets and configuration

| Item | Where | Notes |
|---|---|---|
| DB password, Redis password, key-encryption secret, JWT RSA signing key, SA bootstrap password | SSM Parameter Store (SecureString), generated by Terraform | Read by the instance role at deploy time and written to `/etc/authplatform/*.env` (mode 600) |
| GitHub deploy key (read-only), SMTP password | SSM Parameter Store, created outside Terraform | Keeps them out of Terraform state |
| `git_ref` | SSM Parameter Store | Commit SHA to deploy. Written by CI |
| Non-secret runtime config | `deploy.sh` template | Public URL, token lifetimes, rate limits and similar |

Everything is defined in [`infra/terraform`](infra/terraform). See [`infra/README.md`](infra/README.md) for prerequisites, deploy, release and teardown steps.

---

## 3. CI/CD

Every push to `main` runs the tests and, if they pass, deploys. Pull requests run the tests only.

```mermaid
flowchart TB
    dev["Developer"] -->|"git push main"| gh["GitHub repository"]
    gh --> t1["Backend tests<br/>Java 21, Maven"]
    gh --> t2["SDK and console tests and build<br/>Node 22"]
    t1 --> dep["Deploy job"]
    t2 --> dep
    dep -->|"OIDC token, no stored AWS keys"| role["IAM role<br/>authplatform-prod-github-deploy"]
    role --> p["SSM: write git_ref = commit SHA"]
    role --> cmd["SSM Run Command<br/>document authplatform-prod-deploy"]
    cmd --> inst["EC2: /opt/authplatform/deploy.sh"]
    inst --> s1["fetch commit with read-only deploy key"]
    s1 --> s2["read secrets from SSM and write env files"]
    s2 --> s3["build backend jar and console"]
    s3 --> s4["restart services and wait for health"]
    s4 --> v["Verify public URL<br/>/sa/login and /api/console/csrf"]
```

Security properties of the pipeline:

- GitHub signs in to AWS through **OIDC**. Only workflows on the `main` branch of this repository (matched by its immutable owner and repository IDs) can assume the deploy role.
- The role can do exactly three things: write the `git_ref` parameter, run the one fixed SSM document, and read the command result. It cannot run arbitrary commands on the instance.
- Deploys are serialized. There is **no automatic rollback**: a failed health check fails the run, and the fix is a new commit or a revert. A deploy restarts both services and causes a short interruption.

---

## 4. Capacity and availability

The numbers below were **measured on the production instance** (t4g.small, 2 vCPU) over short runs against `localhost`, so they exclude the load balancer and TLS. Treat them as best-case for the endpoint type measured.

| Workload | Result |
|---|---|
| Backend, light endpoints (CSRF, public keys) | **560 to 810 requests/second**, p95 under 115 ms |
| Console pages (Next.js) | **about 900 requests/second**, p95 40 ms |
| Password check (Argon2) | **about 63 ms each**: roughly **16/second per core**, **about 25/second** with both cores saturated |

What this means in practice:

| Question | Estimate |
|---|---|
| Sustained sign-ins or sign-ups | **about 10 to 15 per second** (600 to 900 per minute) with headroom, because every one runs an Argon2 hash |
| Authenticated API calls | likely **200 to 400 per second** (estimate, not measured: each call verifies a JWT, checks Redis and sometimes queries the database) |
| Concurrent active users | a few hundred comfortably, roughly 1,000 to 2,000 as a ceiling |
| Memory | JVM about 540 MB resident of 2 GB. 2 GB swap as a buffer |
| Database | `db.t4g.micro`: about 100 connections maximum, 20 GB storage |

**Availability (single instance, single AZ):** realistically **about 99.5%**, or 3 to 4 hours of downtime a month. This is a judgment, not an AWS commitment. Specifically:

- A deploy interrupts both services for roughly 15 to 30 seconds.
- A failed instance is not replaced automatically. Rebuilding it with Terraform takes about 6 to 8 minutes.
- RDS and MemoryDB are single nodes with no standby.
- If Redis is unavailable, the rate limiter refuses requests with `503 RATE_LIMIT_UNAVAILABLE`, so sign-ins stop. This is deliberate (fail closed).
- RDS keeps 7 days of backups with point-in-time restore.

**Cost:** roughly **$90 to $100 per month** (load balancer, MemoryDB, RDS, EC2, public IPv4 addresses), paid from account credits. A budget alert is configured.

### Scaling path

```mermaid
flowchart LR
    now["Today<br/>1 x t4g.small<br/>single AZ<br/>about 99.5%"] --> s1["Step 1<br/>fix per-client IP for rate limits<br/>see Known limitations"]
    s1 --> s2["Step 2<br/>bigger instance, e.g. t4g.large<br/>about 2x login capacity, about 2x cost"]
    s2 --> s3["Step 3<br/>Auto Scaling Group over 2 AZs<br/>2+ instances behind the ALB"]
    s3 --> s4["Step 4<br/>RDS Multi-AZ and MemoryDB replica<br/>99.9% and above, about 2 to 2.5x cost"]
```

---

## 5. Low-level design

### 5.1 Backend modules

The backend is a modular monolith under `com.authplatform`. Each business package follows `controller` -> `service` -> `repository` -> `entity`.

| Package | Responsibility |
|---|---|
| `auth` | Console and SDK sign-up, login, OTP, refresh, sessions, JWT issuing, email verification, password reset, per-app key and origin filters |
| `app` | Applications: keys, origins, redirect URLs, MFA policy, token lifetimes, branding icon |
| `role` | Roles, role-owned permissions, user-role assignment and per-user overrides |
| `user` | `Account` (developers and admins) and `AppUser` (end users) |
| `sa` | Platform-admin API, SA login, analytics, first-admin bootstrap |
| `audit` | Append-only audit log |
| `notification` | Email rendering and SMTP delivery |
| `ratelimit` | Redis sliding-window rate limiting |
| `common` | Security configuration, error model, password and token hashing, request IDs |

```mermaid
classDiagram
    direction LR
    class AccountAuthServiceImpl
    class AppUserAuthServiceImpl
    class SessionService {
        +startForAccount()
        +startForAppUser()
        +rotate(rawRefresh)
        +revoke()
        +restoreRevocationCache()
    }
    class SessionReplayRevocationService
    class JwtService {
        +issue() RS256
        +parse(token, audience)
    }
    class MfaService {
        +issue*Otp()
        +verify*Otp()
        +resend*Otp()
    }
    class LoginAttemptService
    class OneTimeTokenService
    class AuditService
    class EmailTemplateService
    class EmailSender {
        <<interface>>
    }
    class SmtpEmailSender
    class PasswordHasher {
        <<interface>>
    }
    class Argon2PasswordHasher
    class TokenHasher {
        <<interface>>
    }
    class Sha256TokenHasher
    class SecureTokenGenerator {
        <<interface>>
    }
    class SecureRandomTokenGenerator

    AccountAuthServiceImpl --> SessionService
    AccountAuthServiceImpl --> JwtService
    AccountAuthServiceImpl --> MfaService
    AccountAuthServiceImpl --> LoginAttemptService
    AccountAuthServiceImpl --> OneTimeTokenService
    AccountAuthServiceImpl --> AuditService
    AccountAuthServiceImpl --> EmailTemplateService
    AccountAuthServiceImpl --> PasswordHasher
    AppUserAuthServiceImpl --> SessionService
    AppUserAuthServiceImpl --> JwtService
    AppUserAuthServiceImpl --> MfaService
    AppUserAuthServiceImpl --> LoginAttemptService
    AppUserAuthServiceImpl --> AuditService
    SessionService --> SessionReplayRevocationService
    SessionService --> TokenHasher
    SessionService --> SecureTokenGenerator
    MfaService --> EmailSender
    MfaService --> EmailTemplateService
    EmailSender <|.. SmtpEmailSender
    PasswordHasher <|.. Argon2PasswordHasher
    TokenHasher <|.. Sha256TokenHasher
    SecureTokenGenerator <|.. SecureRandomTokenGenerator
```

### 5.2 Request pipeline

Every request passes through the Spring Security chain below (order taken from `SecurityConfig`). The key filter and origin filter apply only to the SDK API (`/api/v1/*`). The request-ID filter and the rate limiter are plain servlet filters that run on every request alongside it.

```mermaid
flowchart LR
    req(["Request"]) --> cors["CORS"]
    cors --> csrf["CSRF<br/>cookie token for console and SA"]
    csrf --> key["AppKeyAuthenticationFilter<br/>X-authplatform-Key, /api/v1 only"]
    key --> origin["AppOriginValidationFilter<br/>Origin must be in the app's allow-list"]
    origin --> jwt["JwtAuthenticationFilter<br/>verify RS256, audience, expiry<br/>then check revoked:sid in Redis"]
    jwt --> authz["Authorization rules<br/>by path"]
    authz --> ctl["Controller"]
    ctl --> svc["Service"]
    svc --> db[("PostgreSQL")]
    svc --> red[("Redis")]
    ctl --> err["GlobalExceptionHandler<br/>ApiError JSON with requestId"]
    rid["RequestIdFilter<br/>X-Request-Id on every request"] -.- authz
    rl["RateLimitFilter<br/>per client IP, sliding window in Redis<br/>sign-in, sign-up and reset endpoints"] -.- authz
```

Route groups and who may call them:

| Path | Authentication | JWT audience | CORS |
|---|---|---|---|
| `/api/v1/auth/**` | Public, requires `X-authplatform-Key` and an allowed `Origin` | none | any origin, no credentials |
| `/api/v1/users/**` | Bearer JWT | the application's ID | any origin, no credentials |
| `/api/console/auth/**`, `/api/console/csrf` | Public | none | configured console origins, with credentials |
| `/api/console/**` | HttpOnly cookie JWT | `authplatform-console` | configured console origins, with credentials |
| `/api/sa/auth/**`, `/api/sa/csrf` | Public | none | configured console origins, with credentials |
| `/api/sa/**` | Cookie JWT with role `SA` | `authplatform-sa` | configured console origins, with credentials |
| `/api/public/**`, `/.well-known/jwks.json`, `/actuator/health` | Public | none | n/a |
| everything else under `/actuator/**` | denied | | |
| `/swagger-ui/**`, `/v3/api-docs/**` | only when `AUTH_DOCS_ENABLED=true` (off in production) | | |

### 5.3 Data model

PostgreSQL is the system of record. Flyway applies the 20 migrations in `authplatform/src/main/resources/db/migration` at backend start. Migrations V19 and V20 enforce **tenant isolation** with composite foreign keys and triggers, so a user, role or permission can never be linked across applications.

```mermaid
erDiagram
    ACCOUNTS ||--o{ APPS : owns
    APPS ||--o{ APP_USERS : has
    APPS ||--o{ ROLES : defines
    ROLES ||--o{ PERMISSIONS : owns
    APP_USERS ||--o{ APP_USER_ROLES : holds
    ROLES ||--o{ APP_USER_ROLES : assigned_as
    APP_USERS ||--o{ APP_USER_ROLE_PERMISSION_OVERRIDES : has
    PERMISSIONS ||--o{ APP_USER_ROLE_PERMISSION_OVERRIDES : overridden_by
    ACCOUNTS ||--o{ SESSIONS : "console or SA session"
    APP_USERS ||--o{ SESSIONS : "SDK session"
    SESSIONS ||--o{ SESSION_USED_REFRESH_TOKENS : "replay detection"
    ACCOUNTS ||--o{ EMAIL_TOKENS : receives
    APP_USERS ||--o{ EMAIL_TOKENS : receives
    APPS ||--o{ AUDIT_LOGS : records

    ACCOUNTS {
        uuid id PK
        string email UK
        string password_hash
        string platform_role "USER or SA"
        bool email_verified
        string status
    }
    APPS {
        uuid id PK
        uuid owner_account_id FK
        string publishable_key UK
        string secret_key_hash
        text_array allowed_origins
        string verify_email_url
        string reset_password_url
        bool require_email_verification
        bool mfa_required
        int access_token_ttl_seconds
        int refresh_token_ttl_seconds
        string status
    }
    APP_USERS {
        uuid id PK
        uuid app_id FK
        string email
        string password_hash
        bool email_verified
        string status
    }
    ROLES {
        uuid id PK
        uuid app_id FK
        string name
        bool is_default
        bool enabled
    }
    PERMISSIONS {
        uuid id PK
        uuid app_id FK
        uuid role_id FK
        string key
        bool enabled
    }
    APP_USER_ROLES {
        uuid app_user_id PK
        uuid role_id PK
    }
    APP_USER_ROLE_PERMISSION_OVERRIDES {
        uuid app_user_id PK
        uuid role_id PK
        uuid permission_id PK
        bool granted
    }
    SESSIONS {
        uuid id PK
        uuid account_id FK
        uuid app_user_id FK
        string refresh_token_hash UK
        string previous_refresh_hash
        timestamptz expires_at
        timestamptz revoked_at
    }
    SESSION_USED_REFRESH_TOKENS {
        uuid session_id PK
        string refresh_token_hash PK
    }
    EMAIL_TOKENS {
        uuid id PK
        string type
        string token_hash UK
        timestamptz expires_at
        timestamptz used_at
    }
    AUDIT_LOGS {
        bigint id PK
        uuid app_id
        string actor_type
        string action
        jsonb metadata
        timestamptz created_at
    }
```

Notes: a session belongs to exactly one subject (an account **or** an app user). Permissions are **owned by a role** (the key is unique per role). Audit rows are immutable (migration V4).

### 5.4 Tokens and sessions

| Token | Format | Lifetime (defaults) | Storage |
|---|---|---|---|
| Access token | RS256 JWT with claims `iss, sub, aud, jti, iat, exp, sid, role, roles, permissions` | End users 15 min (per application 60 to 86,400 s). Console and SA 30 min | Cookie only. Never stored server-side |
| Refresh token | Random opaque string | End users 30 days (per application 1 h to 90 days, never shorter than the access token). Console and SA 48 h | Only its **SHA-256 hash** is stored in `sessions` |
| One-time code | 6 digits | 5 minutes, at most 3 resends and 10 wrong attempts | Redis |
| Email verification and reset links | Random token | 24 h and 30 min | Hash in `email_tokens` |

**Refresh rotation with replay detection.** Every refresh issues a new refresh token and invalidates the old one. Used tokens are remembered in `session_used_refresh_tokens`.

```mermaid
sequenceDiagram
    participant C as Client (BFF)
    participant A as Backend API
    participant D as PostgreSQL
    participant R as Redis

    C->>A: POST /refresh with refresh token T1
    A->>D: find session by hash of T1, lock the row
    alt T1 is the current token
        A->>D: store hash of T2, keep hash of T1 as previous
        A-->>C: new access JWT and T2
    else T1 was already rotated
        alt used less than 10 seconds ago (another tab)
            A-->>C: 409 REFRESH_IN_PROGRESS, client retries
        else replay of an old token
            A->>D: revoke the session
            A->>R: SET revoked sid with TTL = access token lifetime
            A-->>C: 400 TOKEN_INVALID
        end
    end
```

**Instant revocation.** Access tokens are stateless, so revoking a session writes `authplatform:revoked:sid:{sid}` to Redis for the access-token lifetime, and `JwtAuthenticationFilter` checks it on every request. On startup the backend rebuilds these keys from the database (`restoreRevocationCache`), so a Redis restart cannot resurrect a revoked session.

### 5.5 Redis keyspace

| Key | Type | Purpose | TTL |
|---|---|---|---|
| `authplatform:rl:ip:{ip}:{path}` | sorted set | sliding-window rate limit | window length |
| `authplatform:lock:fail:{subject}` | counter | failed-login count | lockout window |
| `authplatform:lock:{subject}` | flag | account temporarily locked | lock duration |
| `authplatform:mfa:otp:{challengeId}` | string | pending OTP challenge | 5 min |
| `authplatform:mfa:attempts:{challengeId}` | counter | wrong-code attempts (locked after 10) | 5 min |
| `authplatform:mfa:resends:{challengeId}` | counter | resend count (max 3) | 5 min |
| `authplatform:revoked:sid:{sid}` | flag | revoked session | access-token lifetime |

### 5.6 Security controls

- **Passwords:** Argon2id (Spring Security defaults). 10 to 128 characters, at least one letter and one digit, must not contain the email local part.
- **Rate limits (per client IP):** sign-in endpoints 5 per minute, sign-up 5 per 10 minutes, password-reset and resend endpoints 1,000 per minute. Exceeding returns `429 RATE_LIMITED`.
- **Lockout:** 5 failed sign-ins within 15 minutes locks the account for 15 minutes and emails the owner.
- **Anti-enumeration:** sign-up, forgot-password and OTP-challenge responses are identical whether or not the account exists.
- **Cookies:** HttpOnly everywhere. Console cookies are `SameSite=Strict`; the SDK's cookies are `SameSite=Lax`, `Secure`, and use the `__Host-` prefix in production. The BFF uses a double-submit CSRF token (`X-authplatform-csrf`). The console API uses Spring's cookie CSRF token (`X-XSRF-TOKEN`).
- **Headers:** HSTS, `X-Content-Type-Options`, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`.
- **Tenant isolation:** every end-user query is scoped by application ID, and the database rejects cross-application links.
- **Audit:** sign-ins, failures, password resets, key rotation, application changes and every platform-admin read are recorded.

### 5.7 Error model

All errors return `{"error": {"code", "message", "requestId", "fieldErrors"}}`. Common codes: `VALIDATION_FAILED` 400, `TOKEN_INVALID` 400, `UNAUTHENTICATED` 401, `INVALID_CREDENTIALS` 401, `INVALID_KEY` 401, `MFA_REQUIRED` 401, `MFA_INVALID` 401, `EMAIL_NOT_VERIFIED` 403, `ORIGIN_NOT_ALLOWED` 403, `ACCESS_DENIED` 403, `NOT_FOUND` 404, `EMAIL_TAKEN` 409, `REFRESH_IN_PROGRESS` 409, `ACCOUNT_LOCKED` 423, `RATE_LIMITED` 429, `RATE_LIMIT_UNAVAILABLE` 503.

---

## 6. Repository layout

| Path | Contents |
|---|---|
| [`authplatform/`](authplatform) | Spring Boot backend, Flyway migrations, tests, local `docker-compose.yml` and `.env.example` |
| [`frontend/`](frontend) | Next.js app: public landing page (`/`) and documentation (`/docs`), plus the developer and platform-admin console |
| [`packages/auth-core`](packages/auth-core) | Framework-agnostic SDK client |
| [`packages/auth-nextjs`](packages/auth-nextjs) | Next.js BFF handlers, middleware and server helpers |
| [`packages/auth-react`](packages/auth-react) | React provider, hooks and ready-made sign-in components |
| [`infra/`](infra) | Terraform for AWS and the operations runbook |
| [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml) | Test and deploy pipeline |
| `scripts/`, `start.sh`, `stop.sh` | SDK build script and local development helpers |

## 7. Run it locally

Local development uses Docker only for the supporting services (PostgreSQL, Redis and Mailpit for catching email). Production does not use Docker.

```sh
./start.sh            # starts Postgres, Redis and Mailpit, then the backend on :8080 (creates authplatform/.env from the example)
cd frontend
npm install
npm run dev           # console on http://localhost:3000, API URL defaults to http://localhost:8080
./stop.sh             # stops the Docker services
```

Backend: `http://localhost:8080` (health `/actuator/health`, Swagger UI `/swagger-ui/index.html`). Email arrives in Mailpit at `http://localhost:8025`.

To create the first platform admin locally, set `SA_BOOTSTRAP_ENABLED=true`, `SA_BOOTSTRAP_EMAIL` and `SA_BOOTSTRAP_PASSWORD` in `authplatform/.env`, start the backend once, then set it back to `false`.

Tests:

```sh
cd authplatform && ./mvnw test        # backend
npm ci && npm test                    # SDK packages (repository root)
cd frontend && npm test               # console
```

## 8. Configuration

The backend is configured entirely through environment variables. The important ones:

| Variable | Purpose |
|---|---|
| `SPRING_PROFILES_ACTIVE` | `prod` requires explicit JWT signing keys and secure cookies |
| `DB_URL`, `DB_USER`, `DB_PASSWORD` | PostgreSQL |
| `REDIS_URL` | `redis://` locally, `rediss://user:password@host:6379` for MemoryDB with TLS and ACL |
| `JWT_ISSUER`, `JWT_SIGNING_KEYS`, `JWT_ACTIVE_KID` | Token issuer and signing keys (`kid\|base64-private\|base64-public`, `;`-separated for rotation) |
| `JWT_ACCESS_TTL`, `JWT_REFRESH_TTL`, `JWT_ACCOUNT_ACCESS_TTL`, `JWT_ACCOUNT_REFRESH_TTL` | Default token lifetimes |
| `authplatform_KEY_ENCRYPTION_SECRET` | Encrypts stored secrets |
| `CONSOLE_ALLOWED_ORIGINS` | Origins allowed to call the console and SA APIs with credentials |
| `AUTH_PLATFORM_PUBLIC_BASE_URL` | Public HTTPS URL used in email links and email icons |
| `AUTH_COOKIE_SECURE`, `AUTH_DOCS_ENABLED` | Secure cookies and Swagger UI toggle |
| `RATE_LIMIT_*`, `LOCKOUT_*` | Rate-limit capacities and periods, lockout thresholds |
| `INVITES_PER_HOUR` | Invitations one developer can send per hour (default 200); stops the platform being used as a mail relay |
| `SMTP_*` | Mail server and sender. `SMTP_CONNECTION_TIMEOUT_MS`, `SMTP_READ_TIMEOUT_MS` and `SMTP_WRITE_TIMEOUT_MS` tune the timeouts |
| `SA_BOOTSTRAP_*` | One-time creation of the first platform admin |

The console reads `NEXT_PUBLIC_API_URL` at **build time**. See [`authplatform/.env.example`](authplatform/.env.example) for the full list.

## 9. Known limitations

- **Rate limits are per client IP.** The SDK's BFF calls the platform from the customer's server, and the SDK does not forward the end user's IP, so all end users of one customer application share that server's limit (5 sign-ins per minute). Fix this before onboarding an application with real sign-in traffic.
- **Single point of failure.** One instance, one AZ, single-node database and cache. See [Capacity and availability](#4-capacity-and-availability).
- **No automatic rollback** on a failed deploy.
- **Terraform state is local** (`infra/terraform/terraform.tfstate`, git-ignored). Back it up; it contains secrets.
- **The JWKS endpoint** (`/.well-known/jwks.json`) serializes the library's key-set object directly, so its JSON is not the standard RFC 7517 shape and standard JWT libraries may not parse it. Tokens are verified by the platform itself.
- **The SDK packages are not published to npm yet** (`npm install` is coming soon). They build locally with `npm run build` at the repository root.
- **The console's "API reference" link points at `http://localhost:8080/swagger-ui`**, which does not exist in production (Swagger is disabled there on purpose).
