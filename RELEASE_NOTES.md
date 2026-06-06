# Auth Platform v1.0.0

This is the first stable GitHub release of Auth Platform, a self-hosted authentication service for modern web apps.

## Working Features

- Hosted auth UI for sign in, sign up, OTP, forgot password, reset password, set password, and OAuth consent.
- OAuth 2.0 Authorization Code Flow with PKCE, authorization endpoint, code exchange, callback handling, and consent management.
- Multi-tenant app isolation with app-specific users, redirect URI validation, client credentials, and app lifecycle management.
- Admin console for registration, login/MFA, passkeys, profile/security settings, tenant settings, apps, users, sessions, stats, and login activity.
- Token lifecycle support for RS256 JWT access/refresh tokens, token refresh, revoke, verify, session check, and session event streaming.
- Security controls including HttpOnly cookies, CSRF middleware, rate limiting, secure client-secret verification, email-enumeration-safe forgot-password behavior, forced logout, and DPoP sender-constrained token support.
- Passkey/WebAuthn registration and login flows for both users and admins.
- Email/OTP services for account verification, MFA, login OTP, and password recovery.
- Login event and session tracking with connected-app and consent revocation endpoints.
- TypeScript SDK for Next.js with `AuthProvider`, `useAuth`, `AuthClient`, and server-side proxy helpers.
- Next.js demo app showing login, logout, callback routing, session state, token claim verification, and HttpOnly token handling.
- Production Docker stack for PostgreSQL, Redis, Gunicorn/Uvicorn backend, Nginx reverse proxy, migration runner, Cloudflare tunnels, and the demo frontend.
- GitHub Actions workflow for backend tests and EC2 deployment on pushes to `main`.

## Validation

- Backend tests: `82 passed`.
- SDK build: `npm run build` passes in `packages/auth-sdk`.
- Demo app build: `npm run build` passes in `next-test-app`.

## Release Notes

- The FastAPI API reports version `1.0.0`.
- The SDK package is currently version `3.2.0`.
- The production compose frontend build now points to `next-test-app/Dockerfile`.
- The demo app uses Next.js standalone output for container deployment.
