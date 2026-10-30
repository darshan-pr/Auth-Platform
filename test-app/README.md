# Auth Platform SDK integration app

This app exercises the local workspace packages `@authplatform/auth-core`, `@authplatform/auth-nextjs`, and `@authplatform/auth-react`. Its sign-in component requests an OTP only when MFA is enabled for the app. Sign-in supports OTP resend and OTP-based password recovery; signup supports resending the email-verification message. The `/verify-email` route uses the SDK `VerifyEmail` component, which sends the token to the backend through the same-origin BFF.

Configure the server-only environment in `.env.local`:

```env
AUTH_PLATFORM_BACKEND_URL=http://localhost:8080
AUTH_PLATFORM_PUBLISHABLE_KEY=pk_...
```

In the console application configuration, set the allowed origin to `http://localhost:3001` and the Verify email URL to `http://localhost:3001/verify-email`. If you change these settings after signup, resend the verification email so it contains the updated callback URL.

Build the local packages and start the app from the repository root:

```sh
npm install
npm run build --workspace=@authplatform/auth-core
npm run build --workspace=@authplatform/auth-nextjs
npm run build --workspace=@authplatform/auth-react
npm run dev --workspace=test-app
```

The App Router layout mounts `AuthProvider` and imports the package stylesheet once. Routes import the UI with one line, for example `import { SignIn } from "@authplatform/auth-react";`. Browser requests go only to the same-origin `/api/auth` BFF; the backend URL, app key, and session tokens are not exposed to the auth components.

The auth cards and browser tab icon load the configured application name and icon from the backend using the publishable key. The test app refreshes branding every five seconds while visible, so icon changes in the console appear without restarting or reloading it. Its centered auth layout shows a small “Protected by AuthPlatform.” footer.

Visit `/permissions` to inspect the signed-in app user's granted permission keys and test conditional UI. Create a permission in the console, assign it to a role held by the user, then use **Refresh permissions** to fetch the updated grants. Enter any exact permission key to see whether the demo action button is shown or hidden. This is a client-side UI example; protected backend operations must enforce the same permission themselves.
