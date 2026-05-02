# Auth Platform SDK

Official TypeScript SDK for **Auth Platform** — OAuth 2.0 + PKCE authentication for Next.js apps.

## Install

```bash
npm install auth-platform-sdk
```

## Setup (4 steps)

### 1. Environment Variables

Create `.env.local` in your Next.js project root:

```env
NEXT_PUBLIC_AUTH_SERVER=https://auth.example.com
NEXT_PUBLIC_CLIENT_ID=your-client-id
NEXT_PUBLIC_REDIRECT_URI=http://localhost:3000/callback

# Server-side only — NEVER prefix with NEXT_PUBLIC_
AUTH_CLIENT_SECRET=your-client-secret
```

### 2. Auth Proxy Route

Create `app/api/auth/[...path]/route.ts`:

```typescript
import { createAuthProxy } from 'auth-platform-sdk/server';
import type { NextRequest } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const proxy = createAuthProxy();
type Ctx = { params: Promise<{ path?: string[] }> };
async function handler(req: NextRequest, ctx: Ctx): Promise<Response> {
  return proxy(req, ctx);
}

export const GET  = handler;
export const POST = handler;
```

### 3. Wrap App with AuthProvider

In your `layout.tsx`:

```tsx
import { AuthProvider } from 'auth-platform-sdk/client';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html><body>
      <AuthProvider>{children}</AuthProvider>
    </body></html>
  );
}
```

### 4. Use in Components

```tsx
'use client';
import { useAuth } from 'auth-platform-sdk/client';

export default function Page() {
  const { user, login, logout, isAuthenticated, loading } = useAuth();

  if (loading) return <p>Loading...</p>;
  if (!isAuthenticated) return <button onClick={() => login()}>Sign In</button>;

  return (
    <div>
      <p>Hello {user?.email}!</p>
      <button onClick={logout}>Sign Out</button>
    </div>
  );
}
```

## Security Architecture

```
Browser (client)              Server (proxy)              Auth Server
┌─────────────────┐          ┌───────────────────────┐    ┌──────────────┐
│ PKCE verifier    │  ────►  │ + client_secret        │ ──►│ Validates    │
│ State (CSRF)     │          │ + HttpOnly cookies     │    │ both PKCE &  │
│ Login redirect   │          │ + Token scrubbing      │    │ client_secret│
│ No secrets       │          │ + Cookie cleanup       │    │              │
│ No tokens in JS  │  ◄────  │ { authenticated: true } │ ◄──│ Issues tokens│
└─────────────────┘          └───────────────────────┘    └──────────────┘
```

## API Reference

### Client Exports (`auth-platform-sdk/client`)

| Export | Type | Description |
|--------|------|-------------|
| `AuthClient` | Class | Core OAuth client |
| `AuthProvider` | Component | React context provider |
| `useAuth()` | Hook | Access auth state |
| `AuthUser` | Type | User object shape |
| `AuthContextValue` | Type | useAuth() return type |

### Server Exports (`auth-platform-sdk/server`)

| Export | Type | Description |
|--------|------|-------------|
| `createAuthProxy()` | Function | Route handler factory |
| `AuthProxyOptions` | Type | Factory config |
| `AuthProxyHandler` | Type | Handler function type |

## License

MIT
