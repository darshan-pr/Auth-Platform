import type { ReactNode } from "react";
import { API_BASE } from "../lib/api";
import styles from "./docs-page.module.css";
import { PageHeader } from "./ui";

const sections = [
  { id: "overview", title: "Overview" },
  { id: "how-it-works", title: "How it works" },
  { id: "quick-start", title: "Quick start" },
  { id: "install", title: "Install the SDK" },
  { id: "nextjs", title: "Integrate with Next.js" },
  { id: "flows", title: "Sign-in and account flows" },
  { id: "tokens", title: "Tokens and sessions" },
  { id: "roles", title: "Roles and permissions" },
  { id: "console", title: "Using the console" },
  { id: "security", title: "Security model" },
  { id: "api", title: "API reference" },
  { id: "errors", title: "Error codes" },
  { id: "troubleshooting", title: "Troubleshooting" },
];

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section aria-labelledby={`${id}-title`} className={styles.section} id={id}>
      <h2 id={`${id}-title`}>{title}</h2>
      {children}
    </section>
  );
}

function Code({ children, label }: { children: string; label?: string }) {
  return (
    <figure className={styles.code}>
      {label && <figcaption>{label}</figcaption>}
      <pre>
        <code>{children}</code>
      </pre>
    </figure>
  );
}

function Callout({ children, tone = "info" }: { children: ReactNode; tone?: "info" | "warn" }) {
  return <div className={`${styles.callout} ${tone === "warn" ? styles.warn : ""}`} role="note">{children}</div>;
}

function Table({ head, rows }: { head: string[]; rows: ReactNode[][] }) {
  return (
    <div className={styles.tableWrap}>
      <table>
        <thead>
          <tr>{head.map((cell) => <th key={cell} scope="col">{cell}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index}>{row.map((cell, cellIndex) => <td key={cellIndex}>{cell}</td>)}</tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Steps({ items }: { items: { title: string; body: ReactNode }[] }) {
  return (
    <ol className={styles.flow}>
      {items.map((item) => (
        <li key={item.title}>
          <strong>{item.title}</strong>
          <span>{item.body}</span>
        </li>
      ))}
    </ol>
  );
}

const architecture = `Browser
   |  talks only to your own app
   v
Your Next.js app  --  SDK server route (BFF) at /api/auth/*
   |  tokens live in HttpOnly cookies, never in JavaScript
   |  X-authplatform-Key: pk_live_...
   v
Auth Platform API  -->  PostgreSQL  (users, sessions, roles, audit log)
                   -->  Redis       (rate limits, one-time codes, revoked sessions)
                   -->  Email       (verification links and one-time codes)`;

export function DocsPage() {
  const envExample = `AUTH_PLATFORM_BACKEND_URL=${API_BASE}
AUTH_PLATFORM_PUBLISHABLE_KEY=pk_live_your_application_key
# Optional: your app's public origin, when it sits behind a proxy
AUTH_PLATFORM_ALLOWED_ORIGIN=https://app.example.com
# Reserved for server-to-server use. Server-side only, never NEXT_PUBLIC_
AUTH_PLATFORM_SECRET_KEY=sk_live_your_application_secret`;

  return (
    <div className={styles.page}>
      <PageHeader
        browserTitle="Documentation"
        description="How Auth Platform works, how to connect your application, and how to use the console."
        title="Documentation"
      />
      <div className={styles.layout}>
        <nav aria-label="On this page" className={styles.toc}>
          <h2>On this page</h2>
          <ol>
            {sections.map((section) => (
              <li key={section.id}><a href={`#${section.id}`}>{section.title}</a></li>
            ))}
          </ol>
        </nav>

        <div className={styles.content}>
        <Section id="overview" title="Overview">
          <p>
            Auth Platform is a multi-tenant identity service. You register an application, choose how its users sign in, and add
            sign-in, sign-up, email verification, password reset and session management to your app with the SDK. The platform
            stores users, checks passwords, sends one-time codes by email, issues and rotates tokens, enforces roles and
            permissions, and keeps an audit trail.
          </p>
          <Table
            head={["Who", "What they do", "Where"]}
            rows={[
              ["Platform admin (SA)", "Operates the platform: sees every account, application and end user, and reads the audit log.", <><code>/sa/login</code> (administration console)</>],
              ["Developer", "Creates applications, copies keys, configures sign-in, manages roles and end users.", <><code>/login</code> (developer console)</>],
              ["End user", "Signs in to a developer's application.", "The developer's own app, using the SDK"],
            ]}
          />
        </Section>

        <Section id="how-it-works" title="How it works">
          <p>
            Your application never handles passwords or tokens itself. A small server route from the SDK (a backend-for-frontend,
            or BFF) sits between the browser and Auth Platform.
          </p>
          <Code label="Request path">{architecture}</Code>
          <Steps
            items={[
              { title: "The browser calls your own app", body: <>The SDK mounts a route at <code>/api/auth/*</code> in your Next.js app. The browser never calls Auth Platform directly.</> },
              { title: "Your server calls Auth Platform", body: <>The route adds your application&apos;s publishable key. The platform checks the key, the request origin against your allowed origins, rate limits, the user&apos;s credentials and, if enabled, a one-time code.</> },
              { title: "Tokens go into HttpOnly cookies", body: "On success the platform returns a short-lived access token and a refresh token. The route stores them in HttpOnly cookies, so JavaScript in the browser can never read them." },
              { title: "Sessions renew themselves", body: "When the access token expires, the SDK refreshes it automatically. The refresh token changes on every use, so a stolen copy stops working." },
              { title: "Your server asks who the user is", body: <>Server code calls <code>currentUser()</code> and receives the user&apos;s profile, roles and permissions.</> },
            ]}
          />
          <h3>Key concepts</h3>
          <Table
            head={["Term", "Meaning"]}
            rows={[
              ["Application", "A product you build. It has its own users, roles, permissions, branding, origins and token lifetimes. Users of one application are completely separate from those of another."],
              [<code key="pk">pk_live_…</code>, "Publishable key. Identifies your application and is sent by your server in the X-authplatform-Key header. It is not a password, but keep it in server environment variables."],
              [<code key="sk">sk_live_…</code>, "Secret key. Shown once when created or rotated, and only a hash is stored. Reserved for server-to-server use and not required by the current API. Never expose it in the browser."],
              ["Allowed origins", "The exact origins (for example https://app.example.com or http://localhost:3000) allowed to call the API for your application. Other origins are rejected."],
              ["Role and permission", "Roles group permissions. Each permission belongs to one role, and a user can hold several roles."],
              ["Session", "One signed-in device. It starts at sign-in and ends at sign-out, revocation, expiry or password reset."],
            ]}
          />
        </Section>

        <Section id="quick-start" title="Quick start">
          <Steps
            items={[
              { title: "Create your developer account", body: <>Choose <strong>Sign up</strong> on the sign-in page. Passwords must be 10 to 128 characters, include a letter and a digit, and must not contain the part of your email before the @. Open the verification link we email you (valid for 24 hours).</> },
              { title: "Sign in", body: "Enter your email and password, then the 6-digit code we email you. Codes last 5 minutes and can be resent up to 3 times. Console sign-in always requires this code." },
              { title: "Create an application", body: <>Open <strong>Applications</strong> and create one. Each developer account can own up to 10 applications. See the settings below.</> },
              { title: "Copy the credentials", body: <>On the application&apos;s <strong>Credentials</strong> tab, copy the publishable key. The secret key is shown only once, so store it safely. Rotating the secret replaces it, and the old one stops working.</> },
              { title: "Connect your app", body: <>Add the SDK to your Next.js app as described in <a href="#nextjs">Integrate with Next.js</a>.</> },
            ]}
          />
          <h3>Application settings</h3>
          <Table
            head={["Setting", "What it does"]}
            rows={[
              ["Name", "Shown to your users in the sign-in screens and emails (up to 100 characters)."],
              ["Allowed origins", "Up to 20 origins, each an https:// origin or http://localhost with an optional port. Write the origin exactly: scheme, host and port, no trailing slash or path."],
              ["Verify email URL", <>A page in your app that receives the verification link as <code>?token=…</code>. If empty, the first allowed origin plus <code>/verify-email</code> is used.</>],
              ["Reset password URL", <>A page in your app for link-based password-reset emails. Set it when you create the application: if empty, those links point to <code>http://localhost:3000</code>.</>],
              ["Require email verification", "On by default. Users cannot sign in until they verify their email."],
              ["Require MFA", "When on, every end-user sign-in asks for a one-time code sent by email."],
              ["Status", "Active or Suspended. A suspended application rejects all end-user requests."],
              ["Token lifetimes", "Optional per-application access and refresh token lifetimes. Leave unset to use the platform defaults (see Tokens and sessions)."],
              ["Icon", "Your application icon, shown in the SDK components and emails."],
            ]}
          />
        </Section>

        <Section id="install" title="Install the SDK">
          <p>The SDK is made of three packages:</p>
          <Table
            head={["Package", "Purpose"]}
            rows={[
              [<code key="n">@authplatform/auth-nextjs</code>, "Server route (BFF), middleware and server helpers such as currentUser()."],
              [<code key="r">@authplatform/auth-react</code>, "AuthProvider, hooks and ready-made SignIn, SignUp, VerifyEmail, ForgotPassword and UserButton components."],
              [<code key="c">@authplatform/auth-core</code>, "Framework-agnostic client, used by the React package. Also usable on its own."],
            ]}
          />
          <div className={styles.soon}>
            <div className={styles.soonHead}>
              <strong>npm install</strong>
              <span className={styles.badge}>Coming soon</span>
            </div>
            <pre>
              <code>npm install @authplatform/auth-nextjs @authplatform/auth-react</code>
            </pre>
          </div>
          <Callout>
            <p>
              <strong>The packages are not published to npm yet.</strong> This section will show the install command as soon as they
              are available. The steps below describe how the SDK works so you can plan your integration.
            </p>
          </Callout>
        </Section>

        <Section id="nextjs" title="Integrate with Next.js">
          <p>The SDK targets the Next.js App Router.</p>
          <h3>1. Configure the server environment</h3>
          <Code label=".env.local">{envExample}</Code>
          <h3>2. Mount the server route</h3>
          <Code label="app/api/auth/[...path]/route.ts">{`import { createAuthHandlers } from "@authplatform/auth-nextjs";

const handlers = createAuthHandlers();

export const GET = handlers.GET;
export const POST = handlers.POST;
export const PUT = handlers.PUT;
export const PATCH = handlers.PATCH;
export const DELETE = handlers.DELETE;`}</Code>
          <p>
            The browser calls only <code>/api/auth/*</code>. The backend URL, your keys and the tokens stay on the server.
          </p>
          <h3>3. Add a sign-in page</h3>
          <Code label="app/sign-in/page.tsx">{`"use client";

import { useRouter } from "next/navigation";
import { SignIn } from "@authplatform/auth-react";
import "@authplatform/auth-react/styles.css";

export default function SignInPage() {
  const router = useRouter();
  return <SignIn onSuccess={() => router.replace("/dashboard")} />;
}`}</Code>
          <p>
            <code>SignIn</code> and <code>SignUp</code> render only the branded card. Position them with your own layout. Wrap pages
            that need the signed-in user in <code>AuthProvider</code>. On public pages such as sign-in, use{" "}
            <code>{"<AuthProvider checkSessionOnLoad={false}>"}</code> to skip the session check.
          </p>
          <h3>4. Protect routes</h3>
          <Code label="proxy.ts">{`import { createMiddleware } from "@authplatform/auth-nextjs/middleware";

export default createMiddleware({ signInUrl: "/sign-in" });

export const config = {
  matcher: ["/dashboard/:path*"],
};`}</Code>
          <Callout tone="warn">
            <p>
              <strong>The proxy is a convenience, not the security check.</strong> It only confirms that a session cookie exists.
              Always verify the user on the server with <code>currentUser()</code> or <code>requireAuth()</code>.
            </p>
          </Callout>
          <Code label="Server component">{`import { currentUser, requireAuth } from "@authplatform/auth-nextjs";

const user = await currentUser();   // null when signed out
const me = await requireAuth();     // throws AuthRequiredError when signed out`}</Code>
          <Code label="Client component">{`"use client";
import { AuthProvider, UserButton, useAuth } from "@authplatform/auth-react";

function Account() {
  const { isLoaded, isSignedIn, user } = useAuth();
  if (!isLoaded) return <p>Loading</p>;
  return isSignedIn && user ? <><p>{user.email}</p><UserButton /></> : <p>Signed out</p>;
}

export default function Page() {
  return <AuthProvider><Account /></AuthProvider>;
}`}</Code>
          <h3>5. Verify email</h3>
          <p>
            The verification email links to the <strong>Verify email URL</strong> of your application with <code>?token=…</code>.
            Render <code>VerifyEmail</code> on that page and pass it the token from the URL.
          </p>
          <Code label="app/verify-email/page.tsx">{`import { VerifyEmail } from "@authplatform/auth-react";

export default async function Page({ searchParams }: { searchParams: Promise<{ token?: string }> }) {
  const { token } = await searchParams;
  return token ? <VerifyEmail token={token} /> : <p>Missing verification token.</p>;
}`}</Code>
          <h3>Components and hooks</h3>
          <Table
            head={["Name", "What it does"]}
            rows={[
              [<code key="1">AuthProvider</code>, "Holds session state, refreshes expired tokens, loads your application name and icon, and syncs across tabs."],
              [<code key="2">SignIn</code>, "Email and password sign-in, including the one-time code step when MFA is on."],
              [<code key="3">SignUp</code>, "Registration form. The user receives a verification email."],
              [<code key="4">VerifyEmail</code>, "Confirms the email address from the link token."],
              [<code key="5">ForgotPassword</code>, "Requests a one-time code and sets a new password."],
              [<code key="6">UserButton</code>, "Account menu. On sign-out it offers to end other active sessions."],
              [<code key="7">useAuth</code>, "Returns isLoaded, isSignedIn, user, the session snapshot and retrySession()."],
              [<code key="8">useUser, useSession</code>, "Narrower hooks for just the user or just the session state."],
              [<code key="9">AuthClient</code>, <>From <code>@authplatform/auth-core</code>: signIn, verifyOtp, getUser, getSessions and revokeSession, for non-React code.</>],
            ]}
          />
        </Section>

        <Section id="flows" title="Sign-in and account flows">
          <h3>End-user sign-up and email verification</h3>
          <p>
            A new user is created with your application&apos;s default role. We email a verification link to your Verify email URL.
            If your application requires verification (the default), the user cannot sign in until the link is opened, and a
            sign-in attempt before that returns <code>EMAIL_NOT_VERIFIED</code>. Responses never reveal whether an email is already
            registered.
          </p>
          <h3>Sign-in</h3>
          <p>
            The user submits an email and password. If MFA is off for the application, the platform creates a session and the BFF
            sets the cookies. If MFA is on, the platform returns only a challenge: no user profile and no tokens until the code is
            verified.
          </p>
          <h3>One-time codes</h3>
          <p>
            A code has 6 digits, lasts 5 minutes and can be resent up to 3 times. After 10 wrong attempts the challenge is locked
            and the owner is emailed. Developer and administrator sign-in always requires a code, and this cannot be turned off.
          </p>
          <h3>Staying signed in</h3>
          <p>
            The access token is short-lived. The SDK refreshes it automatically with the refresh token, coordinates refreshes
            across browser tabs, and retries a request after a successful refresh. A temporary network failure is reported as
            an error state without signing the user out.
          </p>
          <h3>Sign-out and active sessions</h3>
          <p>
            Signing out ends the current session. <code>UserButton</code> first checks for other active sessions and lets the user
            end individual devices. Developers can also revoke all of an end user&apos;s sessions from the console.
          </p>
          <h3>Password reset</h3>
          <p>
            The user asks to reset the password and receives a one-time code by email. Submitting the code with a new password
            changes the password, <strong>ends every active session</strong> for that user, and sends a confirmation email.
          </p>
          <h3>Developer and administrator accounts</h3>
          <p>
            Console and administration accounts use the same flow with longer-lived sessions: access tokens last 30 minutes and
            refresh sessions 48 hours. Their tokens travel in HttpOnly cookies set by the platform.
          </p>
        </Section>

        <Section id="tokens" title="Tokens and sessions">
          <Table
            head={["Item", "Default lifetime", "Notes"]}
            rows={[
              ["End-user access token", "15 minutes", "Per application: 60 to 86,400 seconds. A signed RS256 JWT carrying the user, session, roles and permissions."],
              ["End-user refresh token", "30 days", "Per application: 1 hour to 90 days, never shorter than the access token."],
              ["Console and admin access token", "30 minutes", "Platform-wide setting."],
              ["Console and admin refresh token", "48 hours", "Platform-wide setting."],
              ["Email verification link", "24 hours", "Single use."],
              ["Password-reset link", "30 minutes", "Single use."],
              ["One-time code", "5 minutes", "Up to 3 resends."],
            ]}
          />
          <h3>Refresh rotation</h3>
          <p>
            Every refresh returns a new refresh token and invalidates the old one. If an old refresh token is used again, we treat
            it as theft: the whole session is revoked and the user must sign in again. Two browser tabs refreshing at the same moment
            are tolerated for a few seconds (the second receives <code>REFRESH_IN_PROGRESS</code> and retries).
          </p>
          <h3>Immediate revocation</h3>
          <p>
            Revoking a session, resetting a password or changing a user&apos;s permissions takes effect on the very next request, not
            when the access token expires. Lifetime changes to an application apply to sessions created afterwards.
          </p>
        </Section>

        <Section id="roles" title="Roles and permissions">
          <ul>
            <li>Every application starts with a <strong>default role</strong>, assigned to each new user at sign-up.</li>
            <li>Create more roles per application. Role names are unique ignoring case, and a role can be disabled.</li>
            <li>Create <strong>permissions</strong> inside a role. A permission key is unique within its role.</li>
            <li>Assign one or several roles to a user. The user receives the permissions of those roles.</li>
            <li>On a user&apos;s page you can grant or deny a single permission for that user within a role. A deny or grant applies only to that user and only for permissions the role defines.</li>
            <li>Removing a permission from the application also removes the user-level overrides for it.</li>
          </ul>
          <p>
            Roles and permissions appear in the access token and in <code>currentUser()</code>. Changing a user&apos;s permissions
            ends their sessions, so their next sign-in carries the updated access.
          </p>
        </Section>

        <Section id="console" title="Using the console">
          <h3>Developer console</h3>
          <Table
            head={["Page", "What you can do"]}
            rows={[
              ["Overview", "Your account summary and a list of your applications."],
              ["Applications", "List and create applications."],
              ["Application: Configuration", "Name, allowed origins, verify and reset URLs, MFA, token lifetimes and icon."],
              ["Application: Roles & permissions", "Create roles and permissions and set which permissions each role has."],
              ["Application: End users", "Search users and open a user. You can revoke a user's sessions from the list."],
              ["User page", "See a user's details and active sessions, revoke sessions, manage the user's roles and permission overrides, or delete the user permanently."],
              ["Application: Credentials", "See the publishable key and rotate the secret key."],
              ["Application: Activity", "A placeholder for per-application activity. Changes and credential events are already recorded in the audit log."],
              ["Account", "Your profile, active sessions and sign-out."],
            ]}
          />
          <h3>Platform administration</h3>
          <Table
            head={["Page", "What you can do"]}
            rows={[
              ["Overview", "Platform analytics: accounts, applications, end users and operational health."],
              ["Accounts", "All developer accounts. Open one to view its details and set it Active or Suspended."],
              ["Applications", "Every application across the platform, including suspension and secret rotation."],
              ["End users", "End users across all applications."],
              ["Audit logs", "An append-only record of sign-ins, failures, password resets, key rotations and administrator reads."],
              ["Account", "Your administrator profile and sessions. Additional administrators are created by an existing one."],
            ]}
          />
          <p>
            Signing out when you have other active sessions opens a dialog where you can end them individually or sign out only on
            this device.
          </p>
        </Section>

        <Section id="security" title="Security model">
          <ul>
            <li><strong>Passwords</strong> are stored as Argon2id hashes. Refresh tokens and email tokens are stored only as SHA-256 hashes.</li>
            <li><strong>Cookies</strong> are HttpOnly. Console cookies use SameSite=Strict, and SDK cookies in your app use SameSite=Lax. In production SDK cookies are Secure and use the <code>__Host-</code> prefix.</li>
            <li><strong>CSRF protection</strong> applies to every state-changing request, for both the SDK route and the console.</li>
            <li><strong>Origin allow-list:</strong> requests for your application from other origins are rejected.</li>
            <li><strong>Rate limits</strong> per client IP: 5 sign-in attempts per minute, 5 sign-ups per 10 minutes, and 1,000 per minute on password-reset and resend endpoints. Over the limit returns <code>429</code>.</li>
            <li><strong>Lockout:</strong> 5 failed sign-ins within 15 minutes lock the account for 15 minutes, and the owner is emailed.</li>
            <li><strong>Tenant isolation:</strong> every query is scoped to the application, and the database rejects links between applications.</li>
            <li><strong>Audit log:</strong> sign-ins, failures, resets, key rotations and administrator reads are recorded and cannot be edited.</li>
            <li><strong>Transport:</strong> HTTPS everywhere with HSTS. The database and cache require TLS.</li>
          </ul>
        </Section>

        <Section id="api" title="API reference">
          <p>
            Most developers use the SDK, which calls these endpoints for you. The interactive Swagger reference is turned off in
            production. All requests and responses are JSON, and errors use the format described under Error codes.
          </p>
          <h3>End-user API (used by the SDK server route)</h3>
          <p>
            Requires the <code>X-authplatform-Key</code> header and an allowed <code>Origin</code>. Calls under{" "}
            <code>/api/v1/users</code> also need the user&apos;s bearer access token.
          </p>
          <Table
            head={["Endpoint", "Purpose"]}
            rows={[
              [<code key="1">GET /api/v1/auth/application</code>, "Public branding: application name and icon."],
              [<code key="2">POST /api/v1/auth/signup</code>, "Register an end user."],
              [<code key="3">POST /api/v1/auth/verify-email</code>, "Confirm an email token."],
              [<code key="4">POST /api/v1/auth/resend-verification</code>, "Send a new verification link."],
              [<code key="5">POST /api/v1/auth/login</code>, "Password sign-in, or an OTP challenge when MFA is on."],
              [<code key="6">POST /api/v1/auth/login/otp</code>, "Complete sign-in with the emailed code. /login/otp/resend resends it."],
              [<code key="7">POST /api/v1/auth/refresh</code>, "Rotate the refresh token and receive a new access token."],
              [<code key="8">POST /api/v1/auth/logout</code>, "End the current session."],
              [<code key="9">POST /api/v1/auth/forgot-password/otp</code>, "Start a password reset by code. /forgot-password/otp/resend resends it."],
              [<code key="10">POST /api/v1/auth/reset-password/otp</code>, "Set a new password with the code."],
              [<code key="11">POST /api/v1/auth/forgot-password, /reset-password</code>, "Link-based password reset."],
              [<code key="12">GET /api/v1/users/me</code>, "The signed-in user, with roles and permissions."],
              [<code key="13">GET /api/v1/users/me/sessions</code>, "The user's active sessions."],
              [<code key="14">DELETE /api/v1/users/me/sessions/{"{sessionId}"}</code>, "End one session."],
            ]}
          />
          <h3>Developer console API</h3>
          <Table
            head={["Endpoint", "Purpose"]}
            rows={[
              [<code key="1">/api/console/auth/*</code>, "Sign-up, verify email, sign-in with code, refresh, sign-out and password reset for developers."],
              [<code key="2">GET /api/console/me</code>, "Your account."],
              [<code key="3">/api/console/apps</code>, "Create, list, read and update applications, and rotate secrets."],
              [<code key="4">/api/console/apps/{"{id}"}/users</code>, "End users of an application."],
              [<code key="5">/api/console/apps/{"{id}"}/roles, /permissions</code>, "Roles, permissions and user assignments."],
              [<code key="6">/api/console/sessions</code>, "Your active sessions."],
            ]}
          />
          <h3>Administration API</h3>
          <Table
            head={["Endpoint", "Purpose"]}
            rows={[
              [<code key="1">/api/sa/auth/*</code>, "Administrator sign-in, refresh, sign-out and password reset."],
              [<code key="2">GET /api/sa/analytics/overview</code>, "Platform analytics."],
              [<code key="3">/api/sa/accounts</code>, "List, create administrators, view and update accounts."],
              [<code key="4">/api/sa/apps</code>, "View and update any application, rotate secrets, manage its users."],
              [<code key="5">GET /api/sa/users, /api/sa/audit-logs</code>, "End users and the audit log."],
            ]}
          />
        </Section>

        <Section id="errors" title="Error codes">
          <p>
            Errors return <code>{`{ "error": { "code", "message", "requestId", "fieldErrors" } }`}</code>. Include the{" "}
            <code>requestId</code> when you contact support.
          </p>
          <Table
            head={["Code", "HTTP", "Meaning"]}
            rows={[
              [<code key="1">VALIDATION_FAILED</code>, "400", "The request is invalid. See fieldErrors."],
              [<code key="2">TOKEN_INVALID</code>, "400", "A link token or refresh token is invalid, used or expired."],
              [<code key="3">OTP_EXPIRED</code>, "400", "The one-time code has expired."],
              [<code key="4">UNAUTHENTICATED</code>, "401", "Sign-in is required or the session has ended."],
              [<code key="5">INVALID_CREDENTIALS</code>, "401", "Email or password is incorrect."],
              [<code key="6">INVALID_KEY</code>, "401", "The application key is invalid."],
              [<code key="7">MFA_REQUIRED / MFA_INVALID</code>, "401", "A one-time code is needed, or the code is wrong."],
              [<code key="8">EMAIL_NOT_VERIFIED</code>, "403", "The user has not verified their email."],
              [<code key="9">ORIGIN_NOT_ALLOWED</code>, "403", "The request origin is not in the application's allowed origins."],
              [<code key="10">ACCESS_DENIED</code>, "403", "Not allowed, or a CSRF check failed."],
              [<code key="11">APP_SUSPENDED / USER_BLOCKED</code>, "403", "The application or the user is suspended or blocked."],
              [<code key="12">NOT_FOUND</code>, "404", "The resource does not exist."],
              [<code key="13">EMAIL_TAKEN / ROLE_NAME_TAKEN</code>, "409", "The email or role name already exists."],
              [<code key="14">APP_LIMIT_REACHED</code>, "409", "You reached the application limit for your account."],
              [<code key="15">REFRESH_IN_PROGRESS</code>, "409", "Another refresh is completing. Retry shortly."],
              [<code key="16">ACCOUNT_LOCKED</code>, "423", "Too many failed sign-ins. Try again later."],
              [<code key="17">RATE_LIMITED</code>, "429", "Too many requests. Wait for the Retry-After seconds."],
              [<code key="18">RATE_LIMIT_UNAVAILABLE</code>, "503", "Sign-in protection is temporarily unavailable. Retry shortly."],
              [<code key="19">INTERNAL_ERROR</code>, "500", "Unexpected server error."],
            ]}
          />
        </Section>

        <Section id="troubleshooting" title="Troubleshooting">
          <Table
            head={["Symptom", "What to check"]}
            rows={[
              [<code key="1">ORIGIN_NOT_ALLOWED</code>, "Add the exact origin of your app (scheme, host and port, no trailing slash) to the application's allowed origins."],
              [<code key="2">INVALID_KEY</code>, <>Check <code>AUTH_PLATFORM_PUBLISHABLE_KEY</code> on the server, and that it belongs to this application.</>],
              ["429 Too many requests", "Per-IP limits apply. Wait for the number of seconds in the Retry-After header."],
              ["503 on sign-in", "The rate-limit store is unreachable. Retry in a few seconds. If it persists, tell your platform administrator."],
              ["Verification or reset email opens the wrong page", "Set the application's Verify email URL and Reset password URL to pages in your app."],
              ["No email or code arrives", "Check spam. Codes last 5 minutes and can be resent up to 3 times. Ask your administrator to confirm outgoing mail is configured."],
              ["Account is temporarily locked", "Five failed sign-ins lock the account for 15 minutes. Wait, or reset the password with a code."],
              ["User was signed out unexpectedly", "A password reset, a permission change, a revoked session or a reused refresh token ends sessions. The user signs in again."],
              ["Sign-in page loops back to itself", "Public pages should use checkSessionOnLoad={false}, and protected routes should verify with currentUser()."],
            ]}
          />
        </Section>

        <p className={styles.footer}>Auth Platform documentation.</p>
        </div>
      </div>
    </div>
  );
}
