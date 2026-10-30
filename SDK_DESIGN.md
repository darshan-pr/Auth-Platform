# Auth Platform SDK Design

Status: Discovery complete; implementation follows this contract.

## Scope and decisions

- Package scope: `@authplatform/*`.
- Supported framework target: Next.js App Router first. Pages Router support is not part of the first release; the core package remains framework-agnostic so a Pages Router adapter can be added later. Next.js 16 consumers use `proxy.ts`; the exported helper retains the `createMiddleware` name for compatibility.
- Integration target: `test-app/` in this workspace. It is a Next.js 16.4.2 App Router application with strict TypeScript and no existing authentication code. `next-test-app/` is an older OAuth demo and is not the target because the current Spring backend exposes no OAuth provider endpoints.
- OAuth is intentionally out of scope. The backend exposes application-user authentication under `/api/v1/auth/*`, not `/oauth/authorize` or `/oauth/token`.
- Browser-to-backend calls are prohibited. Browser code calls only the test application's `/api/auth/*` BFF route. The BFF calls Spring Boot with the publishable application key and stores access/refresh tokens in HttpOnly cookies.
- The publishable key is server configuration in the first integration. The secret key is also server-only, but the current Stage-1 backend has no endpoint that consumes it; it will not be sent or exposed by the SDK until a backend contract exists for it.

## Backend auth contract discovered

Source of truth: `authplatform/src/main/java/com/authplatform/auth/controller/` and related DTO/service classes.

| Method | Backend path | Request | Success response | Auth / headers | SDK treatment |
|---|---|---|---|---|---|
| POST | `/api/v1/auth/signup` | `name`, `email`, `password` | 201 `UserSummary` | `X-authplatform-Key: <publishable key>` | BFF forwards; returns sanitized user, never credentials |
| POST | `/api/v1/auth/login` | `email`, `password`, optional `mfaCode` | 200 `LoginResponse`, or 202 MFA challenge | Publishable key | BFF forwards; removes `accessToken` and `refreshToken`, sets HttpOnly cookies |
| POST | `/api/v1/auth/login/otp` | `challengeId`, `code` | 200 `LoginResponse` | Publishable key | BFF forwards; stores tokens in cookies |
| POST | `/api/v1/auth/refresh` | `refreshToken` | 200 `LoginResponse` | Publishable key | BFF injects refresh cookie; rotates cookies; never accepts browser-supplied token over the public API |
| POST | `/api/v1/auth/logout` | `refreshToken` | 204 | Publishable key | BFF injects refresh cookie, forwards, and clears both cookies |
| POST | `/api/v1/auth/verify-email` | `token` | 200 `{emailVerified:true}` | Publishable key | BFF forwards token from the verification form only |
| POST | `/api/v1/auth/resend-verification` | `email` | 202 generic message | Publishable key | BFF forwards; generic response preserved |
| POST | `/api/v1/auth/forgot-password` | `email` | 202 generic message | Publishable key | BFF forwards; generic response preserved |
| POST | `/api/v1/auth/reset-password` | `token`, `newPassword` | 200 generic message | Publishable key | BFF forwards; no token returned |
| GET | `/api/v1/users/me` | none | 200 `UserSummary` | Publishable key + `Authorization: Bearer <access token>` | BFF injects access cookie |
| GET | `/api/v1/auth/mfa/status` | none | 200 MFA status | Publishable key + bearer access token | BFF injects access cookie |
| GET | `/.well-known/jwks.json` | none | JWK set | Public | Not needed by the browser SDK; available for server verification |

The backend returns errors in `{error:{code,message,requestId,fields}}` from `GlobalExceptionHandler`, with validation errors in `fields`. Servlet filters can return plain `sendError` responses, so the BFF will normalize both JSON and non-JSON upstream errors into the SDK's stable `AuthError` shape.

Backend token facts:

- App-user login returns access and refresh tokens in JSON; the SDK must move them into cookies at the BFF boundary.
- Refresh rotates the refresh token through `SessionService` and detects reuse.
- JWTs are RS256, include issuer/audience/expiration/session ID, and are verified by the backend.
- The browser must not receive the raw token fields. This is an SDK boundary rule even though the backend currently returns them to server callers.

## Existing frontend and test-app findings

- `frontend/` is the platform console, not the third-party consumer SDK. Its `lib/api.ts` calls the backend directly from browser code and is therefore not reusable as the SDK.
- `test-app/` uses Next.js 16.4.2, App Router, TypeScript 5, strict mode, and npm. It is the installed-package integration target and contains the BFF route, `proxy.ts`, auth pages, protected page, and server-user page.
- `next-test-app/` uses Next.js 16.2.4 and an existing `auth-platform-sdk` package with OAuth/PKCE routes. Those routes target `/oauth/*`, `/token/*`, and an `authServer` contract absent from the stable Spring backend, so that implementation is not reused.
- The new React components will use CSS variables and an `appearance` object rather than assuming Tailwind or the console stylesheet.

## Proposed package architecture

```text
packages/
  auth-core/       framework-agnostic models, validation, API client, errors, session state
  auth-react/      client-only provider, hooks, accessible components, CSS-variable theme
  auth-nextjs/     server-only BFF route factory, middleware, auth/currentUser/requireAuth
test-app/
  app/api/auth/[...path]/route.ts  one-line BFF mount
```

### `@authplatform/auth-core`

- No React, Next, Node, or backend URL dependency.
- Uses relative `/api/auth` by default through an injectable `fetch` implementation.
- Exports public DTOs, `AuthError`, validation schemas, `AuthClient`, and session state types.
- Uses cookies implicitly through `credentials: include`; it never reads tokens or storage.
- Exposes `signUp`, `signIn`, `verifyOtp`, `signOut`, `refresh`, `forgotPassword`, `resetPassword`, `verifyEmail`, `resendVerification`, and `getUser`.

### `@authplatform/auth-react`

- All client entry points begin with `"use client"`.
- `AuthProvider` owns the session state machine and exposes explicit refresh behavior through `useAuth().refresh()`.
- `useAuth`, `useUser`, and `useSession` expose sanitized state only.
- Components are accessible, keyboard-operable, labelled, and expose loading, validation, empty, and error states.
- Appearance uses CSS variables plus an `appearance` prop. No secret or backend URL is read by this package.

### `@authplatform/auth-nextjs`

- Server entry points import `server-only`.
- `createAuthHandlers()` returns Next App Router handlers for `/api/auth/[...path]`.
- `createMiddleware`/`proxy.ts` protects navigation optimistically by checking the HttpOnly access cookie. `auth()`, `currentUser()`, and `requireAuth()` remain authoritative and perform the server-side user check; middleware does not make a backend call on every navigation.
- `auth()`, `currentUser()`, and `requireAuth()` read/verify the server session without exposing tokens to client components.
- Env names: `AUTH_PLATFORM_BACKEND_URL`, `AUTH_PLATFORM_PUBLISHABLE_KEY`, `AUTH_PLATFORM_SECRET_KEY` (reserved and never sent until the backend supports secret authentication), and optional `AUTH_PLATFORM_ALLOWED_ORIGIN`.
- Startup/config validation fails clearly when backend URL or publishable key is missing. Secret key is not required by the current backend contract, so its absence is not a startup failure.

## BFF and cookie design

- Cookie names are prefixed `__Host-` in production, with `Path=/`, `Secure`, `HttpOnly`, and `SameSite=Lax`.
- Access cookie lifetime follows the JWT expiry; refresh cookie lifetime follows the backend `refreshExpiresIn`, which reports the remaining per-app refresh-session lifetime.
- Login and refresh responses are sanitized before reaching the browser.
- Logout and failed refresh clear both cookies.
- BFF accepts only an allowlisted operation path; it never becomes an arbitrary proxy.
- Mutating BFF calls require same-origin/allowed-origin validation and a double-submit CSRF token. SDK UI fetches add the CSRF header automatically.
- Apps may override platform access and refresh lifetimes within backend-enforced bounds. The SDK refresh client coalesces concurrent refreshes, and navigation middleware allows the BFF to refresh when the access cookie has expired but the refresh cookie remains.
- Upstream headers, stack traces, SQL text, internal URLs, and secret values are never copied into SDK errors.

## Threat model

| Threat | Control |
|---|---|
| XSS reads access/refresh tokens | HttpOnly cookies; no local/session storage; no token fields in client responses |
| CSRF against cookie mutations | Same-origin/Origin validation plus double-submit CSRF token |
| Backend URL or key leakage | Server-only env access in `auth-nextjs`; no `NEXT_PUBLIC_*` secrets |
| Arbitrary backend proxying | Fixed operation allowlist and fixed backend base URL |
| User enumeration | Preserve generic forgot/resend responses and normalize error messages |
| Replay of refresh token | Backend rotation/reuse detection; BFF never exposes refresh tokens |
| Open redirect | No SDK-controlled post-login redirect in the Stage-1 flow; caller routes are local allowlisted paths |
| Dependency/supply-chain risk | Minimal dependencies, lockfiles, npm audit, package files whitelist, no source maps/tests in tarballs |
| Accidental server code in browser bundle | `server-only`, package exports, client/server entry-point separation, post-build bundle grep |

## Open questions and backend gaps

1. The backend SDK surface uses `X-authplatform-Key` and does not consume the application secret. The SDK will keep the secret server-only but cannot claim secret-key authentication until a backend endpoint defines it.
2. The backend public API returns raw token fields to server callers. No backend change is required for the BFF design, but direct browser calls must remain unsupported.
3. The current backend has no dedicated `/api/v1/session` endpoint; `GET /api/v1/users/me` is the session/user probe.
4. OAuth/provider endpoints are absent by design and will not be emulated by this SDK.
5. Backend filter error responses are not always the global JSON error contract. The SDK boundary will normalize these without changing the backend contract.

## Release and verification gates

- Build ESM, CJS, and declaration outputs with an explicit exports map.
- Publish only `dist`, package README, and license through `files` whitelists; do not publish source maps or tests.
- Unit-test core validation, error normalization, and session transitions.
- Component-test accessible server-rendered markup; browser interaction and automated WCAG audits remain a release follow-up.
- Build and install packed tarballs into `test-app` as real dependencies.
- Build `test-app`, grep `.next` for backend URLs, secret env names/values, and server-only imports, and verify no token is present in browser-readable storage/cookies.
- Run an end-to-end flow against the running Spring backend when an application publishable key and test credentials are supplied through `.env.local`; never commit those values.
