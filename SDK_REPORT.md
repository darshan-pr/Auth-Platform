# Auth Platform SDK final report

Date: 2026-10-21

## Outcome

Built and integrated three publishable packages:

- `@authplatform/auth-core@0.1.0`: framework-independent DTOs, validation, normalized errors, cookie-based BFF client, and session state.
- `@authplatform/auth-react@0.1.0`: client-only provider, hooks, accessible auth forms, user button, and CSS-variable appearance support.
- `@authplatform/auth-nextjs@0.1.0`: server-only BFF handlers, CSRF/origin enforcement, HttpOnly cookie handling, middleware/proxy helper, `auth()`, `currentUser()`, and `requireAuth()`.

The discovery and endpoint contract are documented in [SDK_DESIGN.md](SDK_DESIGN.md). The test app consumes packed tarballs from `artifacts/`, not SDK source files; its dependencies and BFF mount are in `test-app/package.json` and `test-app/app/api/auth/[...path]/route.ts`.

No Spring Boot backend changes were required for this SDK boundary. The SDK uses the existing publishable-key contract and deliberately keeps `AUTH_PLATFORM_SECRET_KEY` server-only and unused until the backend defines a secret-authenticated endpoint.

## Verified security checklist

| Area | Result | Evidence |
|---|---|---|
| BFF-only browser boundary | Pass | `packages/auth-nextjs/src/handlers.ts:100-117`; browser client defaults to relative `/api/auth` in `packages/auth-core/src/index.ts:231-239`; static bundle scan was clean for backend URL, key names, `/api/v1`, and `server-only`. |
| Auth token storage | Pass | Auth cookies are HttpOnly, `SameSite=Lax`, `Path=/`, and production `__Host-` cookies in `packages/auth-nextjs/src/handlers.ts:80-91` and `packages/auth-nextjs/src/config.ts:30-42`. No `localStorage` or `sessionStorage` references were found in the client bundle. |
| Token response leakage | Pass | Response allowlists are in `packages/auth-nextjs/src/public.ts:19-59`; tests explicitly pass fake access/refresh tokens and assert they are absent in `packages/auth-nextjs/test/public.test.ts:5-19`. |
| CSRF and origin checks | Pass | Constant-time double-submit comparison and exact origin validation are in `packages/auth-nextjs/src/handlers.ts:49-67`; a live local request without CSRF returned `403 ACCESS_DENIED`. |
| Unauthenticated session behavior | Pass | Missing access cookie is rejected before upstream proxying in `packages/auth-nextjs/src/handlers.ts:131-134`; live local `/api/auth/me` returned `401 UNAUTHENTICATED`. |
| Error boundary | Pass | Upstream errors are converted to stable public messages in `packages/auth-nextjs/src/handlers.ts:40-46,143-148`; the error test proves backend text (`database detail`) is not exposed. |
| Config/secret handling | Pass with backend contract limitation | Required server config validation is in `packages/auth-nextjs/src/config.ts:17-27`; `.env.example` uses non-secret placeholders and no `NEXT_PUBLIC_*` secret. The secret key is intentionally not sent because the discovered backend contract does not consume it. |
| Open proxy prevention | Pass | Fixed operation allowlist is in `packages/auth-nextjs/src/handlers.ts:11-16`; backend paths are constructed by `backendPath()` at lines 94-98. |
| Open redirect prevention | Pass | Middleware restricts the configured sign-in URL to a local path in `packages/auth-nextjs/src/middleware.ts:8-11`. |
| Package boundary | Pass | `files` whitelists, ESM/CJS/types exports, peer dependencies, and CSS side-effect declaration are in each package manifest; packed archives contain no tests, source maps, or `.env` files. |
| Minified release output | Pass | `scripts/build-package.mjs:18-29` emits declarations and minifies both ESM and CJS with esbuild. |
| Dependency audit | Pass | `npm audit --omit=dev --audit-level=high --offline` returned `found 0 vulnerabilities`. |
| Secret scanner | Unverified | `gitleaks` is not installed in this environment. Manual scan found only the ignored local `authplatform/.env`; `git check-ignore` confirmed `authplatform/.gitignore:1`. Verify in CI with `gitleaks detect --redact` or equivalent. |

## Build and test evidence

The following completed successfully after the final changes:

```text
npm run build                         PASS
npm test                              PASS
  auth-core                           3 tests passed
  auth-nextjs                         4 tests passed
  auth-react                          1 component markup test passed
npm run pack:packages                 PASS
npm install --legacy-peer-deps        PASS
npm run build --workspace=test-app    PASS
npm audit ...                         found 0 vulnerabilities
```

The test app production build emitted routes for `/api/auth/[...path]`, `/protected`, `/server-user`, `/sign-in`, and `/sign-up`, and reported `ƒ Proxy (Middleware)`.

The installed tarballs were smoke-tested through both ESM and CJS imports. The final browser-only `.next/static` scan was clean for:

```text
AUTH_PLATFORM_BACKEND_URL
AUTH_PLATFORM_PUBLISHABLE_KEY
AUTH_PLATFORM_SECRET_KEY
server-only
/api/v1
localhost:8080
accessToken
refreshToken
localStorage
sessionStorage
```

The live local BFF checks, using dummy values and an intentionally unavailable backend, produced:

- `GET /api/auth/csrf`: `200`, `Cache-Control: no-store`, non-HttpOnly CSRF cookie with `Secure; SameSite=lax` in production mode.
- `GET /api/auth/me` without an access cookie: `401 UNAUTHENTICATED`.
- `POST /api/auth/login` without a CSRF token: `403 ACCESS_DENIED`.

## Remaining findings and exact verification steps

### SDK-001 — Medium — Real end-to-end authentication is unverified

Evidence: the test app contains placeholders in `test-app/.env.example:1-5`; the live BFF request with `AUTH_PLATFORM_BACKEND_URL=http://127.0.0.1:18080` and dummy `pk_test` could verify boundary behavior but the upstream was unavailable, so sign-up, sign-in, refresh rotation, email verification, password reset, and logout against Spring were not completed.

Verify by creating a disposable application in the backend, placing its publishable key in an uncommitted `test-app/.env.local`, starting Spring Boot/Postgres/Redis, then exercising `/sign-up`, `/sign-in`, `/protected`, `/server-user`, refresh, verification, reset, and logout. Assert cookie attributes and that `document.cookie` contains only the CSRF cookie.

### SDK-002 — Medium — Application secret key has no backend use yet

Evidence: `SDK_DESIGN.md:11-12,109-115` records that the discovered backend authenticates SDK calls with `X-authplatform-Key` and exposes no secret-authenticated SDK contract. `packages/auth-nextjs/src/config.ts:4-5` therefore documents `secretKey` as reserved and never sends it.

Impact: the SDK cannot claim server-to-server secret-key authentication or secret-key rotation semantics yet. This is intentionally not emulated with an invented header.

Verify/fix when the backend defines the contract: specify header/authentication semantics, rotation/grace behavior, audit behavior, and a contract test; then make `secretKey` required only for server operations that actually need it.

### SDK-003 — Low — Pages Router adapter is not included

Evidence: `SDK_DESIGN.md:8` documents App Router first; the working integration uses Next 16 `proxy.ts` at `test-app/proxy.ts:1-6`.

Verify when needed by adding a Pages Router API-route adapter and integration test. No client contract change is required for `auth-core` or `auth-react`.

### SDK-004 — Low — Browser interaction and WCAG automation are not fully verified

Evidence: `packages/auth-react/test/component.test.mjs:7-12` verifies server-rendered labels and absence of token-bearing fields, but there is no Playwright/axe run in this workspace.

Verify with Playwright against the running test app: keyboard-only sign-up/sign-in, focus order, validation announcements, error states, protected navigation, and axe WCAG AA checks.

### SDK-005 — Low — Load/performance baseline is not included

Evidence: no k6 or equivalent load script exists in the SDK workspace, and no real backend was available for a meaningful latency measurement.

Verify with a disposable environment and a load test covering login, `/api/auth/me`, refresh, and list/page navigation. Record p50/p95/p99, throughput, error rate, CPU, memory, Redis, and database utilization before changing implementation.

## Decision list

1. Decide whether the backend will add a server-secret authentication contract. Until then, keep `AUTH_PLATFORM_SECRET_KEY` present only as a server-side reserved configuration value.
2. Decide whether Pages Router support is required for the first published version. App Router is the verified target.
3. Provide a disposable backend application key and test account for the end-to-end gate.
4. Add CI tools for gitleaks, Playwright/axe, and k6 before production publication.

There are no verified Blocker or High findings in the implemented SDK scope. The items above are documented limitations or unverified gates, not claims that the corresponding production behavior has been proven.
