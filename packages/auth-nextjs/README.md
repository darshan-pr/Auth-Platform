# @authplatform/auth-nextjs

Next.js App Router integration with an HttpOnly-cookie BFF.

```ts
// app/api/auth/[...path]/route.ts
import { createAuthHandlers } from "@authplatform/auth-nextjs";

export const { GET, POST } = createAuthHandlers();
```

Required server environment:

```env
AUTH_PLATFORM_BACKEND_URL=http://localhost:8080
AUTH_PLATFORM_PUBLISHABLE_KEY=pk_...
AUTH_PLATFORM_SECRET_KEY=sk_... # server-only; not consumed by the current backend contract
```

Then use `AuthProvider` and the components from `@authplatform/auth-react`. The browser calls only `/api/auth/*`; backend URL, keys, and tokens remain server-side.

The BFF also provides `GET /api/auth/sessions` and `DELETE /api/auth/sessions/{sessionId}` for the signed-in app user. It forwards the HttpOnly access cookie to the backend and exposes only safe session metadata.

The BFF also exposes `GET /api/auth/application` for public application branding. The auth React provider uses this publishable-key-authenticated endpoint to display the application name and icon saved in the developer console.
