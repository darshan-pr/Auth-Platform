# Auth Platform

Stage 1 is a Spring Boot 3.5 modular monolith with console account auth, app management, tenant-scoped SDK auth, RS256 JWTs, refresh-token rotation, Redis-backed limits/lockout, Flyway/Postgres persistence, and Mailpit email delivery.

## Run locally

```sh
cp .env.example .env
docker compose up --build
```

Backend: `http://localhost:8080`; health: `/actuator/health`; Swagger UI: `http://localhost:8080/swagger-ui/index.html`; OpenAPI JSON: `http://localhost:8080/v3/api-docs`; Mailpit: `http://localhost:8025`.

The Swagger UI is generated from the controller mappings and includes bearer JWT and `X-authplatform-Key` security schemes.

For local source development, run the backend from the IDE with automatic project builds enabled; Spring Boot DevTools restarts the application when compiled classes change. Running `./mvnw spring-boot:run` starts the current compiled code but does not continuously compile source files. The Docker Compose backend is a packaged image with no source bind mount, so after backend code or Flyway migration changes, rebuild and recreate it with `docker compose up --build backend`. Flyway applies new migrations at backend startup, not while the process is already running.

Nginx is deliberately not included in the current stage. Console and SA access and refresh tokens use HttpOnly cookies. The SDK's Next.js BFF also stores its tokens in same-origin HttpOnly cookies and forwards them to the backend as bearer tokens; direct API integrations are responsible for their own token storage.

## JWT signing keys

When `JWT_SIGNING_KEYS` is empty in a non-production profile, the backend creates a local development key once and reuses it across restarts. By default it is stored at `~/.authplatform/dev-jwt-signing-key`; Docker Compose stores it in the persistent `dev-jwt-keys` volume. Removing that file or volume intentionally rotates the key and invalidates existing access tokens. Production requires a stable `JWT_SIGNING_KEYS` value; keep old key IDs in the configured key ring during planned rotation.

## Browser API demo

Start the backend, then serve the demo page from the project directory:

```sh
python3 -m http.server 5500 --bind 127.0.0.1 --directory demo
```

Open `http://127.0.0.1:5500`. Enter the API base URL and manually run the buttons for console auth, app management, SDK auth, user `/me`, JWKS, Swagger, or any custom request. Console and SA sign-in support resending the active login OTP; both account types also use an emailed OTP to reset passwords. Console email verification can be resent separately. SDK email verification and SDK password reset continue to use email links/tokens. For SDK email verification, set the app's Verify email URL to `http://127.0.0.1:5500/` (the demo also accepts `/verify-email`), then open the email link. The demo reads the token from the URL and submits it to the SDK verification API.

The application automatically imports the local `.env` file when launched from the project directory, so IDE runs do not need a separate shell `source` step. Docker Compose still supplies its environment variables normally.

## SA platform access

SA access is intentionally not publicly sign-up-able. To create the first local SA account, temporarily set these values in `.env`:

```env
SA_BOOTSTRAP_ENABLED=true
SA_BOOTSTRAP_EMAIL=platform-admin@example.com
SA_BOOTSTRAP_NAME=Platform Admin
SA_BOOTSTRAP_PASSWORD=use-a-strong-password
```

Start the backend once, then set `SA_BOOTSTRAP_ENABLED=false`. Bootstrap is skipped after an SA account already exists and never overwrites an existing account. Additional SA accounts can be created by an authenticated SA through `POST /api/sa/accounts`.

SA authentication uses `POST /api/sa/auth/login`, HttpOnly access and refresh cookies, and JWT audience `authplatform-sa`. `POST /api/sa/auth/login/otp/resend` resends the active sign-in code. `POST /api/sa/auth/forgot-password` starts an OTP reset flow; resend with `POST /api/sa/auth/forgot-password/otp/resend` and complete it with `POST /api/sa/auth/reset-password`. Console accounts use the matching paths under `/api/console/auth`. Protected platform routes are under `/api/sa/**` and include analytics, all developer accounts, all apps, all SDK users, account/app/user management, secret rotation, and append-only audit-log access. The demo page includes an SA testing block.

When MFA is pending, console, SA, and SDK login endpoints return only an unauthenticated OTP challenge (`authenticated: false`, `otpRequired: true`, `challengeId`, `expiresIn`, and `message`). No user/account profile or session tokens are returned until the OTP is successfully verified. The SDK BFF preserves this challenge-only response and does not expose a user object before authentication.

## Platform account token lifetimes

SA and Console account sessions use `JWT_ACCOUNT_ACCESS_TTL` and `JWT_ACCOUNT_REFRESH_TTL`, defaulting to 30 minutes and 48 hours. These settings are separate from SDK app-user token defaults. Platform tokens are sent as HttpOnly cookies (`authplatform_access` / `authplatform_refresh` for Console and `authplatform_sa_access` / `authplatform_sa_refresh` for SA); the refresh token is intentionally not returned in JSON or exposed to `document.cookie`.

## SDK application token lifetimes

Each SDK application can inherit the SDK platform defaults `JWT_ACCESS_TTL` and `JWT_REFRESH_TTL` (15 minutes and 30 days by default) or set its own lifetimes when created or updated through the console app configuration. The API fields are `accessTokenTtlSeconds` and `refreshTokenTtlSeconds`; omit both to inherit the platform defaults. To reset an existing app to those defaults, send `usePlatformTokenTtls: true` in its update request.

Custom app values are bounded: access tokens must last 60–86,400 seconds, and refresh sessions 3,600–7,776,000 seconds. Refresh lifetime must be at least the access-token lifetime. The SDK login, OTP-verification, and refresh responses include `expiresIn` for the access token and `refreshExpiresIn` for the remaining refresh-session lifetime. The Next.js BFF uses these values for its HttpOnly cookie expirations.

Refresh-token rotation does not extend the session's absolute `expiresAt`. App lifetime changes apply to sessions created after the change; existing sessions keep their original access-token lifetime and refresh expiry. Console and SA account sessions continue to use the platform-wide values.

## Application and user permissions

Application permissions are defined per app and assigned to application roles. The user page shows the permissions enabled for each role in the same role accordion. User-level Add/Remove controls are scoped to that user and role; they cannot create access to a permission that is not enabled for that role in the application. An application-level permission removal cascades to its user overrides and immediately removes it from effective access. Without a user override, an assigned user inherits the role's permissions. Set a user-role override with `PUT /api/console/apps/{appId}/users/{userId}/roles/{roleId}/permissions/{permissionId}` and a JSON body such as `{"granted":true}`; the equivalent `/api/sa/` route is available to platform administrators. Updating a user permission revokes that user's sessions so subsequent sign-ins receive current access.

Flyway migration V10 introduces user overrides, and V11 scopes them to application roles and migrates existing overrides. Both are applied when the backend starts with Flyway enabled.

## Session management

Authenticated console and SA accounts can list their active sessions with `GET /api/console/sessions` or `GET /api/sa/sessions`. Revoke one of their own sessions with `DELETE /api/console/sessions/{sessionId}` or `DELETE /api/sa/sessions/{sessionId}`. SDK app users use `GET /api/v1/users/me/sessions` and `DELETE /api/v1/users/me/sessions/{sessionId}` with their app key and access token. Session responses include device/IP metadata and a `current` flag, never refresh tokens.

App administrators can inspect and revoke an app user's sessions at `/api/console/apps/{appId}/users/{userId}/sessions` or `/api/sa/apps/{appId}/users/{userId}/sessions`. `DELETE` on the sessions collection revokes all of that user's sessions. Permanently delete an app user with `DELETE /api/console/apps/{appId}/users/{userId}` or `DELETE /api/sa/apps/{appId}/users/{userId}`. Deletion revokes sessions before removing the user and dependent role assignments.

## Gmail SMTP

For Gmail, create an app password after enabling 2-Step Verification, then place these values in the local `.env` file (never commit it):

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-account@gmail.com
SMTP_PASSWORD=your-16-character-app-password
SMTP_FROM=your-account@gmail.com
SMTP_AUTH=true
SMTP_STARTTLS_ENABLE=true
SMTP_STARTTLS_REQUIRED=true
```

Docker Compose automatically reads `.env` for its variable interpolation, and direct IDE/Maven launches import the project `.env` automatically when started from this directory. Google documents Gmail SMTP on port 587 with STARTTLS and app-password requirements in its [Gmail SMTP settings](https://support.google.com/mail/answer/7104828) and [app-password guide](https://support.google.com/mail/answer/185833).
