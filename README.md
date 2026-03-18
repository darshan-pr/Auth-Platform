# Auth Platform

Self-hosted authentication with OAuth 2.0 Authorization Code Flow (PKCE), email OTP, RS256 JWTs, multi-tenant app management, passkey (WebAuthn) support, and a built-in admin console.

## Highlights

- **OAuth 2.0 + PKCE** with hosted login page (no client secrets on the frontend)
- **Email/password + OTP** verification with brute-force lockout protection
- **Passkey (WebAuthn)** with server-side cryptographic signature verification (ECDSA/RS256)
- **RS256 access/refresh tokens** with per-app expiry and auto-refresh
- **Multi-tenant**: multiple apps, isolated users, per-app redirect URIs
- **Admin Console** for apps, users, and stats — secured with HttpOnly JWT cookies
- **Sender-Constrained Tokens (DPoP)** via RFC 9449
- **Drop-in JavaScript SDK** for any frontend

## Services and URLs

| Service | URL | Notes |
|---------|-----|-------|
| Backend API | http://localhost:8000 | FastAPI service |
| API Documentation | http://localhost:8000/api/docs | Professional developer docs with SDK download |
| OpenAPI Spec (Swagger) | http://localhost:8000/docs | Interactive API testing |
| Hosted Login | http://localhost:8000/oauth/authorize | Rendered by the platform |
| Admin Console | http://localhost:8000/login | Served by the backend |

## Quick Start (Docker)

```bash
cp .env.example .env   # fill in SMTP credentials + secrets
docker compose up -d
```

Open the Admin Console at **http://localhost:8000/login** and create your first application.

## Run Locally (5 steps)

1. **Install deps**
```bash
cd backend
python3.10+ -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```
2. **Create `.env`** (PostgreSQL, Redis, SMTP)
```env
DATABASE_URL=postgresql://user:password@localhost:5432/auth_platform
REDIS_URL=redis://localhost:6379
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
JWT_SECRET=change-me-in-production
ALLOWED_ORIGINS=http://localhost:3000
```
3. **Migrations** — run SQL files in `migrations/` against the database, including the new `algorithm` column:
```sql
-- Required for passkey crypto verification
ALTER TABLE passkey_credential ADD COLUMN IF NOT EXISTS algorithm INTEGER DEFAULT -7 NOT NULL;
```
4. **Start backend**
```bash
uvicorn app.main:app --reload --port 8000
```
5. **Open** Admin Console at http://localhost:8000/login and create your first application.

## Endpoint Summary

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth/authorize` | GET | Start OAuth flow, renders hosted login page |
| `/oauth/authenticate` | POST | Verify credentials on the login page |
| `/oauth/token` | POST | Exchange authorization code for tokens (PKCE) |
| `/auth/signup` | POST | Register a user |
| `/auth/login` | POST | Login with email + password |
| `/auth/request-otp` | POST | Request OTP for an email |
| `/auth/verify-otp` | POST | Verify OTP and get tokens |
| `/auth/forgot-password` | POST | Request password reset (no email enumeration) |
| `/token/refresh` | POST | Refresh an access token |
| `/token/verify` | POST | Verify a token's validity |
| `/admin/register` | POST | Register a new admin + tenant |
| `/admin/login` | POST | Admin login (sets HttpOnly cookie) |
| `/admin/logout` | POST | Admin logout (clears cookie) |
| `/admin/apps` | GET/POST | List or create applications |
| `/admin/apps/{id}` | GET/PUT/DELETE | Manage a specific application |
| `/admin/apps/{id}/credentials` | GET | Get masked app credentials |
| `/admin/apps/{id}/regenerate-secret` | POST | Rotate app secret (plaintext shown once) |
| `/admin/users` | GET/POST | List or create users |
| `/admin/stats` | GET | Dashboard statistics |
| `/admin/login-events` | GET | View auth events (paginated) |

## JavaScript SDK (copy-paste ready)

1. **Download the SDK**
   - Visit http://localhost:8000/api/docs and click the download button
   - Or directly: http://localhost:8000/static/auth-sdk.js

2. **Add your config**
```javascript
const AUTH_CONFIG = {
  AUTH_SERVER: 'http://localhost:8000',
  CLIENT_ID: 'your-client-id',
  REDIRECT_URI: window.location.origin + window.location.pathname,
};
```
3. **Wire it up**
```html
<script src="config.js"></script>
<script src="auth-sdk.js"></script>
<script>
  const auth = new AuthClient(AUTH_CONFIG);
  await auth.handleCallback();

  if (auth.isAuthenticated()) {
    const user = auth.getUser();
    console.log('Hello', user.email);
    auth.startAutoRefresh();
  } else {
    auth.login(); // Redirects to hosted login
  }
</script>
```
4. **Call your APIs**
```javascript
const token = auth.getAccessToken();
const res = await fetch('/api/notes', {
  headers: { Authorization: `Bearer ${token}` }
});
```

## Architecture Map

```
backend/
  app/
    api/          # Route handlers (auth, admin, oauth, token, health)
    models/       # SQLAlchemy models (user, app, refresh_token, passkeys)
    schemas/      # Pydantic request/response schemas
    services/     # Business logic (JWT, OTP, OAuth, password, mail, passkey, CSRF, DPoP)
    templates/    # Hosted login page (Jinja2)
    static/       # Admin console (app.js, admin-auth.html)
  keys/           # RSA key pair for JWT signing
  migrations/     # SQL migration scripts
  tests/          # Pytest test suite
frontend/
  admin-console/  # Admin dashboard (vanilla JS + Lucide icons)
  sdk/            # Downloadable JS SDK
sample-app/       # Notes app showing end-to-end integration
docker-compose.yml
run.sh
```

---

## Security Features

### 🔐 Passkey / WebAuthn (Server-Side Verification)

Full server-side cryptographic verification of WebAuthn assertions:

- **COSE key parsing** — supports `ES256` (P-256 ECDSA) and `RS256` (RSA PKCS#1 v1.5)
- **Signature verification** — verifies `authenticatorData + clientDataHash` using the stored public key
- **Sign count** — detects cloned authenticators by checking the counter
- **OTP gate** — users must verify their email via OTP before completing passkey registration

3-step registration flow: `POST /oauth/passkey/register/begin` → `POST /oauth/passkey/register/verify-otp` → `POST /oauth/passkey/register/complete`

### 🚫 Email Enumeration Prevention

The `POST /auth/forgot-password` endpoint always returns HTTP 200 with a generic message regardless of whether the email exists, preventing user enumeration attacks:

```json
{ "message": "If an account exists with this email, a password reset code has been sent." }
```

### 🛡️ Brute-Force Protection

Redis-backed attempt tracking with automatic lockout on auth endpoints:

| Endpoint | Max Attempts | Lockout Duration |
|----------|-------------|-----------------|
| `POST /auth/login` | 5 | 15 minutes |
| `POST /admin/login` | 5 | 15 minutes |
| OTP verification | 5 | 15 minutes |

- Returns `429 Too Many Requests` with `Retry-After` on lockout
- Counters reset automatically on successful authentication
- Fails open if Redis is unavailable (no service disruption)

### 🍪 Admin Token Security (HttpOnly Cookie)

Admin JWTs are **never exposed to JavaScript**:

- Login/register sets an `HttpOnly; SameSite=Lax` cookie named `admin_token`
- The response body contains tenant metadata only (no `access_token` field)
- `POST /admin/logout` clears the cookie server-side
- API clients can still use `Authorization: Bearer <token>` (header takes precedence)

### 🔑 App Secret Hashing

Application secrets are stored as **SHA-256 hashes** at rest:

- Plaintext secret is shown **only once** — on creation or after `POST /admin/apps/{id}/regenerate-secret`
- `GET /admin/apps/{id}/credentials` returns a masked hint: `{ "app_secret_hint": "****a1b2" }`
- The application verifies secrets using `hmac.compare_digest` (timing-safe)
- Legacy plaintext secrets (pre-migration) are supported for backward compatibility

### 🚦 Rate Limiting

Redis-backed sliding window rate limiter on all auth endpoints:

| Variable | Default | Description |
|---|---|---|
| `RATE_LIMIT_LOGIN` | 5 | Max login attempts per minute per IP |
| `RATE_LIMIT_OTP` | 3 | Max OTP requests per minute per IP |
| `RATE_LIMIT_SIGNUP` | 10 | Max signups per minute per IP |
| `RATE_LIMIT_GENERAL` | 60 | Max general API calls per minute per IP |

Returns `429 Too Many Requests` with `Retry-After` header when exceeded.

### 🛑 Anti-CSRF (Double-Submit Cookie)

Middleware that sets a `csrf_token` cookie on GET requests. State-changing requests (POST/PUT/DELETE) require a matching `X-CSRF-Token` header. Exempted for:
- `application/json` API requests (inherently CSRF-safe)
- Bearer-authenticated requests (API-to-API)
- `/oauth/token` endpoint (protected by PKCE)

### 📍 IP & Location Tracking

Every authentication event records:
- Client IP (supports `X-Forwarded-For`, `X-Real-IP` headers)
- Geolocation (city, region, country, coordinates, ISP) via [ip-api.com](http://ip-api.com)
- Results cached in Redis for 24h

View events via `GET /admin/login-events` (paginated, filterable by `event_type` and `app_id`).

### 🔒 Sender-Constrained Tokens (DPoP)

[RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) DPoP implementation:

1. Client sends a `DPoP` header with a signed JWS proof during `/oauth/token`
2. Server validates the proof and binds the token via `cnf.jkt` claim
3. Returns `token_type: "DPoP"` instead of `"bearer"`
4. `/token/verify` enforces DPoP proof for tokens with `cnf.jkt` claims

### 🔐 Client Authentication (Confidential Clients)

The `/oauth/token` endpoint supports optional `client_secret` for backend apps:
- **Public clients** (SPAs): PKCE-only
- **Confidential clients** (backend apps): PKCE + `client_secret`

Secrets are verified against their SHA-256 hash using `hmac.compare_digest`.

---

## Running Tests

```bash
cd backend
source .venv/bin/activate   # Python 3.10+
python -m pytest tests/ -v
```

**59 tests** across 4 files:

| File | Coverage |
|------|----------|
| `test_security_fixes.py` | Passkey OTP, email enumeration, brute-force, HttpOnly cookies, secret hashing |
| `test_isolation.py` | Multi-tenant data isolation, JWT tenant claims |
| `test_security.py` | Rate limiting, CSRF, login event recording |
| `test_tenant.py` | Admin registration, login, tenant management |

---

## Deployment

- **Docker**: `docker compose up -d` — includes Postgres, Redis, and the backend.
- **Railway**: ready out-of-the-box. Create project, add PostgreSQL + Redis, set env vars, deploy.
- **Other platforms**: any host with Python 3.10+, PostgreSQL, Redis (Heroku, Render, Fly.io, AWS, GCP, etc.).

---

## License

MIT