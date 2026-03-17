# Auth Platform

Self-hosted authentication with OAuth 2.0 Authorization Code Flow (PKCE), email OTP, RS256 JWTs, multi-tenant app management, and a built-in admin console.

## Highlights
- OAuth 2.0 + PKCE with hosted login page (no client secrets on the frontend)
- Email/password + OTP verification and passkey-ready model
- RS256 access/refresh tokens with per-app expiry and auto-refresh
- Multi-tenant: multiple apps, isolated users, per-app redirect URIs
- Admin Console for apps, users, and stats
- Drop-in JavaScript SDK for any frontend

## Services and URLs
| Service | URL | Notes |
|---------|-----|-------|
| Backend API | http://localhost:8000 | FastAPI service |
| API Documentation | http://localhost:8000/api/docs | Professional developer docs with SDK download |
| OpenAPI Spec (Swagger) | http://localhost:8000/docs | Interactive API testing |
| Hosted Login | http://localhost:8000/oauth/authorize | Rendered by the platform |
| Admin Console | http://localhost:3000 | Default password: Darsh@26 |

## Run Locally (5 steps)
1) **Install deps**
```bash
cd backend
pip install -r requirements.txt
```
2) **Create .env** (PostgreSQL, Redis, SMTP)
```env
DATABASE_URL=postgresql://user:password@localhost:5432/auth_platform
REDIS_URL=redis://localhost:6379
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
ALLOWED_ORIGINS=*
```
3) **Migrations** — run your SQL files in `migrations/` against the database.
4) **Start services**
```bash
./run.sh              # backend + admin console
./run.sh backend      # backend only (port 8000)
./run.sh admin        # admin console only (port 3000)
```
5) **Open** Admin Console at http://localhost:3000 and create your first application.

## API Docs
- **Developer Documentation**: http://localhost:8000/api/docs — Beautiful, professional docs with examples and SDK download (like Google Cloud or Next.js docs)
- **Interactive API Testing**: http://localhost:8000/docs — Swagger UI for testing endpoints
- **OpenAPI JSON**: http://localhost:8000/openapi.json — For SDK generation or tooling

## JavaScript SDK (copy-paste ready)
1) **Download the SDK**
- Visit http://localhost:8000/api/docs and click the download button
- Or directly download: http://localhost:8000/static/auth-sdk.js
- Or copy from `sample-app/auth.js`
2) **Add your config**
```javascript
// config.js
const AUTH_CONFIG = {
  AUTH_SERVER: 'http://localhost:8000',
  CLIENT_ID: 'your-client-id',
  REDIRECT_URI: window.location.origin + window.location.pathname,
};
```
3) **Wire it up**
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
4) **Call your APIs**
```javascript
const token = auth.getAccessToken();
const res = await fetch('/api/notes', {
  headers: { Authorization: `Bearer ${token}` }
});
```
- Full integration example: [sample-app/README.md](sample-app/README.md) and the Notes app files beside it.

## Endpoint Summary
| Endpoint | Method | Description |
|----------|--------|-------------|
| /oauth/authorize | GET | Start OAuth flow, renders hosted login page |
| /oauth/authenticate | POST | Verify credentials on the login page |
| /oauth/token | POST | Exchange authorization code for tokens (PKCE) |
| /auth/request-otp | POST | Request OTP for an email |
| /auth/verify-otp | POST | Verify OTP and get tokens |
| /token/refresh | POST | Refresh an access token |
| /token/verify | POST | Verify a token's validity |
| /admin/apps | GET/POST | List or create applications |
| /admin/apps/{id} | GET/PUT/DELETE | Manage a specific application |
| /admin/users | GET/POST | List or create users |
| /admin/stats | GET | Dashboard statistics |

## Architecture Map
```
backend/
  app/
    api/          # Route handlers (auth, admin, oauth, token, health)
    models/       # SQLAlchemy models (user, app, refresh_token, passkeys)
    schemas/      # Pydantic request/response schemas
    services/     # Business logic (JWT, OTP, OAuth, password, mail)
    templates/    # Hosted login page (Jinja2)
    static/       # Admin console build
  keys/           # RSA key pair for JWT signing
  migrations/     # SQL migration scripts
frontend/
  admin-console/  # Admin dashboard (vanilla JS + Lucide icons)
  sdk/            # Downloadable JS SDK
sample-app/       # Notes app showing end-to-end integration
run.sh            # Service runner
```

## Security Features

### Rate Limiting
Redis-backed sliding window rate limiter applied to all auth endpoints. Configurable via environment variables:

| Variable | Default | Description |
|---|---|---|
| `RATE_LIMIT_LOGIN` | 5 | Max login attempts per minute per IP |
| `RATE_LIMIT_OTP` | 3 | Max OTP requests per minute per IP |
| `RATE_LIMIT_SIGNUP` | 10 | Max signups per minute per IP |
| `RATE_LIMIT_GENERAL` | 60 | Max general API calls per minute per IP |

Returns `429 Too Many Requests` with `Retry-After` header when exceeded.

### Anti-CSRF (Double-Submit Cookie)
Middleware that sets a `csrf_token` cookie on GET requests. State-changing requests (POST/PUT/DELETE) require a matching `X-CSRF-Token` header. Exempted for:
- `application/json` API requests (inherently CSRF-safe)
- Bearer-authenticated requests (API-to-API)
- `/oauth/token` endpoint (protected by PKCE)

### IP & Location Tracking
Every authentication event (login, signup, OAuth, admin login) records:
- Client IP (supports `X-Forwarded-For`, `X-Real-IP` headers)
- Geolocation data (city, region, country, coordinates, ISP) via [ip-api.com](http://ip-api.com)
- Results cached in Redis for 24h to minimize API calls

View events via `GET /admin/login-events` (paginated, filterable by `event_type` and `app_id`).

### Client Authentication (OAuth Token Exchange)
The `/oauth/token` endpoint now supports optional `client_secret` for confidential clients:
- **Public clients** (SPAs): PKCE-only (existing behavior, no change)
- **Confidential clients** (backend apps): PKCE + `client_secret`

### Sender-Constrained Tokens (DPoP)
[RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) DPoP implementation. Opt-in per request:
1. Client sends a `DPoP` header with a signed JWS proof during `/oauth/token`
2. Server validates the proof and binds the token via `cnf.jkt` claim
3. Returns `token_type: "DPoP"` instead of `"bearer"`
4. `/token/verify` enforces DPoP proof for tokens with `cnf.jkt` claims

## Deployment
- **Railway**: ready out-of-the-box. Steps — create project, add PostgreSQL + Redis, set env vars, deploy. See [RAILWAY_DEPLOYMENT.md](RAILWAY_DEPLOYMENT.md) for details.
- **Other platforms**: any host with Python 3.8+, PostgreSQL, Redis, and environment variables (Heroku, Render, Fly.io, AWS, GCP, Azure, etc.).

## Admin Console
- Default password: Darsh@26 (change after first login).
- Manage applications (client IDs, redirect URIs, session settings) and users; view dashboard stats.

## License
MIT