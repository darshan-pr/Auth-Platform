# @authplatform/auth-react

Accessible client components and hooks for Auth Platform.

```tsx
"use client";
import { AuthProvider, SignIn } from "@authplatform/auth-react";
import "@authplatform/auth-react/styles.css";

export default function LoginPage() {
  return <AuthProvider checkSessionOnLoad={false}><SignIn /></AuthProvider>;
}
```

The provider communicates only with the mounted Next.js BFF at `/api/auth`. It never reads an access or refresh token. Session restoration runs on mount by default; set `checkSessionOnLoad={false}` on public-only routes such as sign-in and sign-up to avoid an unnecessary `/me` request. Wrap protected routes with a provider using the default behavior to restore an existing session.

`AuthProvider` loads the application name and icon configured in the developer console through the same-origin BFF and updates the browser tab icon. Branding refreshes on mount and when the page becomes visible; set `brandingRefreshIntervalMs` to a positive value to poll for changes while the page is open. Set `applicationName` or `applicationIconUrl` only when you intentionally want to override the saved branding.

Session checks refresh expired access tokens automatically and coordinate refreshes across tabs where the browser supports Web Locks. A temporary session-check failure is reported as `snapshot.status === "error"` without treating the user as signed out or clearing their cookies; call `useAuth().retrySession()` to try again.

`<SignIn />` and `<SignUp />` render only the branded, responsive auth card. They do not add a full-screen background, centering, or page footer; position them with your app's own layout.

`<UserButton />` checks for other active sessions when the user chooses to sign out. If any exist, it opens a dialog where the user can revoke individual sessions or sign out on the current device.
