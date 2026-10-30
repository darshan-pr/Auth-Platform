# @authplatform/auth-core

Framework-agnostic Auth Platform client. It talks to a relative BFF path by default and never stores or exposes access/refresh tokens.

```ts
import { AuthClient } from "@authplatform/auth-core";

const auth = new AuthClient();
await auth.signIn({ email, password });
const user = await auth.getUser();
const sessions = await auth.getSessions();
await auth.revokeSession(sessions[0].id);
```

The browser must mount the Next.js BFF from `@authplatform/auth-nextjs`; direct browser calls to Spring Boot are intentionally unsupported.

Session listing returns safe device metadata and marks the current session. Revocation accepts a session ID and never exposes refresh-token material.

When MFA is required, `signIn()` returns an unauthenticated OTP challenge with `user: null`; the user profile is returned only after `verifyOtp()` succeeds.
