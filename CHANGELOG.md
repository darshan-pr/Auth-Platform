# Changelog

## v1.0.0 - 2026-06-06

### Added
- Production-ready FastAPI authentication service release baseline.
- OAuth 2.0 Authorization Code + PKCE flow with hosted auth screens.
- Multi-tenant application and user management through the admin console.
- Email/password auth, OTP verification, forgot/reset password, and set-password flows.
- Passkey/WebAuthn support for user and admin authentication.
- RS256 JWT access and refresh tokens, refresh/revoke/verify endpoints, and DPoP token protection support.
- CSRF protection, rate limiting, secure cookies, tenant isolation, and login event tracking.
- TypeScript `auth-platform-sdk` package for Next.js apps with client hooks and server proxy helpers.
- Docker Compose production stack with PostgreSQL, Redis, backend, Nginx, migration runner, Cloudflare tunnel, and demo Next.js app.
- GitHub Actions CI for backend tests plus EC2 deployment workflow for pushes to `main`.

### Verified
- Backend automated tests pass with Python 3.13: `82 passed`.
- SDK TypeScript build passes: `npm run build` in `packages/auth-sdk`.
- Next.js demo production build passes: `npm run build` in `next-test-app`.

### Notes
- CI is configured to validate with Python 3.11 on GitHub Actions.
- Local `python3` on this machine is Python 3.9, which cannot parse the test suite's modern union type syntax; use `.venv/bin/python` or `backend/.venv/bin/python`.
