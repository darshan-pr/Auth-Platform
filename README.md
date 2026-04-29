# Auth Platform
A production-minded, self-hosted authentication platform for modern apps, built with OAuth 2.0 + PKCE, multi-tenant isolation, passkeys (WebAuthn), and hosted auth screens.

GitHub: https://github.com/darshan-pr/Auth-Platform
LinkedIn:https://www.linkedin.com/feed/update/urn:li:activity:7433885576686256128/
## Tech Stack

---

<p>
  <img alt="FastAPI" src="https://img.shields.io/badge/FASTAPI-059669?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img alt="Python" src="https://img.shields.io/badge/PYTHON-1E3A8A?style=for-the-badge&logo=python&logoColor=FFD43B" />
  <img alt="Uvicorn" src="https://img.shields.io/badge/UVICORN-111827?style=for-the-badge" />
  <img alt="Gunicorn" src="https://img.shields.io/badge/GUNICORN-111827?style=for-the-badge" />
  <img alt="SQLAlchemy" src="https://img.shields.io/badge/SQLALCHEMY-DC2626?style=for-the-badge" />
  <img alt="PostgreSQL" src="https://img.shields.io/badge/POSTGRESQL-334155?style=for-the-badge&logo=postgresql&logoColor=white" />
  <img alt="Redis" src="https://img.shields.io/badge/REDIS-B91C1C?style=for-the-badge&logo=redis&logoColor=white" />
  <img alt="OAuth 2.0" src="https://img.shields.io/badge/OAUTH_2.0-0F172A?style=for-the-badge" />
  <img alt="PKCE" src="https://img.shields.io/badge/PKCE-1D4ED8?style=for-the-badge" />
  <img alt="JWT RS256" src="https://img.shields.io/badge/JWT_RS256-7C3AED?style=for-the-badge&logo=jsonwebtokens&logoColor=white" />
  <img alt="DPoP" src="https://img.shields.io/badge/DPOP-0369A1?style=for-the-badge" />
  <img alt="Jinja2" src="https://img.shields.io/badge/JINJA2-78350F?style=for-the-badge&logo=jinja&logoColor=white" />
  <img alt="Vanilla JS" src="https://img.shields.io/badge/VANILLA_JS-F59E0B?style=for-the-badge&logo=javascript&logoColor=111827" />
  <img alt="Docker" src="https://img.shields.io/badge/DOCKER-0EA5E9?style=for-the-badge&logo=docker&logoColor=white" />
  <img alt="Docker Compose" src="https://img.shields.io/badge/DOCKER_COMPOSE-2563EB?style=for-the-badge&logo=docker&logoColor=white" />
  <img alt="Next.js" src="https://img.shields.io/badge/NEXT.JS-111827?style=for-the-badge&logo=nextdotjs&logoColor=white" />
  <img alt="Pytest" src="https://img.shields.io/badge/PYTEST-0F766E?style=for-the-badge&logo=pytest&logoColor=white" />
  <img alt="HTTPX" src="https://img.shields.io/badge/HTTPX-1F2937?style=for-the-badge" />
</p>



## Project Overview

Auth Platform helps teams ship secure login and authorization without rebuilding auth from scratch for every product.

It provides:
- A hosted user auth experience (sign in, sign up, forgot/reset password)
- OAuth 2.0 Authorization Code Flow with PKCE
- Multi-tenant application management from a built-in admin console
- Token issuance/verification, refresh, and advanced protection features (including DPoP)

## Why This Project

Most small and mid-size teams struggle with:
- Implementing secure auth flows correctly
- Managing auth across multiple apps/tenants
- Handling OTP, passkeys, token refresh, and security hardening consistently

This platform solves that by centralizing identity and security into one reusable service.

## Core Capabilities

- Hosted authentication UI with app branding support (including per-app logo)
- OAuth authorization endpoint + secure code exchange
- App-specific and tenant-aware user identity boundaries
- Email/password login with optional OTP enforcement
- Forgot password and set-password flows with secure email delivery
- Passkey registration/authentication (WebAuthn)
- Admin console for app/user lifecycle management
- Login event tracking and operational stats

## Security Features

- RS256 JWT access and refresh tokens
- HttpOnly cookie protection for admin sessions
- Brute-force and rate-limit protections
- Email enumeration-safe forgot-password behavior
- Per-app secret handling with secure verification
- CSRF protection for browser-sensitive routes
- DPoP support for sender-constrained tokens (RFC 9449 style)

## Architecture Snapshot

```text
backend/
  app/
    api/            # auth, oauth, admin, token, health endpoints
    services/       # OTP, JWT, OAuth, mail, passkey, security utilities
    models/         # SQLAlchemy entities
    templates/      # hosted auth and reset-password pages
    static/         # admin console and docs UI
    assets/         # UI/media assets
  migrations/       # SQL schema migrations
  tests/            # automated backend tests

next-app/           # sample client app integration
frontend/           # additional frontend assets
scripts/run.sh      # local/dev/prod-like service runner
scripts/run-docker.sh # production docker runner
```

## Getting Started

### Option A: Docker (fastest)

```bash
cp .env.example .env
# Fill database, redis, smtp, jwt values

docker compose up -d
```

### Option B: Local Script Runner

```bash
source .venv/bin/activate
bash scripts/run.sh
```

`scripts/run.sh` supports:
- Dev mode (`uvicorn --reload`)
- Deployment mode (`gunicorn` + Cloudflare tunnel URL output)
- Controlled startup/shutdown for backend and tunnels

## Important Runtime Behavior

To avoid migration deadlocks/noise in multi-worker mode:
- Migrations are run once before server workers boot
- Worker startup migration execution is disabled via `RUN_DB_MIGRATIONS_ON_STARTUP=false`

You can still force startup migrations by setting:

```env
RUN_DB_MIGRATIONS_ON_STARTUP=true
```

## Key URLs (Local)

- Backend API: `http://localhost:8000`
- Swagger/OpenAPI: `http://localhost:8000/docs`
- Developer Docs UI: `http://localhost:8000/api/docs`
- Admin Console: `http://localhost:8000/login`

## Environment Variables (Core)

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL` | Redis connection for OTP/rate limiting/state |
| `JWT_SECRET` | JWT signing and security secret |
| `SMTP_SERVER`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` | Email delivery configuration |
| `AUTH_SERVER_URL` | Public auth server base URL |
| `AUTH_PLATFORM_URL` | Public platform URL used in templates/links |
| `ALLOWED_ORIGINS` | CORS allowlist |
| `RUN_DB_MIGRATIONS_ON_STARTUP` | Toggle boot-time migrations |

## Testing

```bash
cd backend
source .venv/bin/activate
python -m pytest tests/ -v
```

## Deployment Notes

This project can be deployed on Railway, Render, Fly.io, AWS, GCP, or any platform that supports:
- Python runtime
- PostgreSQL
- Redis

For production, use:
- TLS everywhere
- strong secrets
- managed Postgres/Redis
- SMTP provider with domain verification

## License

MIT
