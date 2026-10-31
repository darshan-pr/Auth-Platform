import Link from "next/link";
import { ArchitectureDiagram } from "./architecture-diagram";
import styles from "./landing-page.module.css";

const routeSnippet = `import { createAuthHandlers } from "@authplatform/auth-nextjs";

const handlers = createAuthHandlers();

export const GET = handlers.GET;
export const POST = handlers.POST;`;

const pageSnippet = `"use client";
import { useRouter } from "next/navigation";
import { SignIn } from "@authplatform/auth-react";

export default function SignInPage() {
  const router = useRouter();
  return <SignIn onSuccess={() => router.replace("/dashboard")} />;
}`;

const features = [
  ["Sign-up and sign-in", "Email and password accounts for each application, with accessible, branded React components."],
  ["Verification and password reset", "Verification links and emailed one-time codes, sent under your application's own name and icon."],
  ["One-time-password MFA", "Require an emailed code at sign-in for any application with a single setting."],
  ["Session management", "Short-lived access tokens, rotating refresh tokens, and per-device sessions that users and developers can revoke."],
  ["Roles and permissions", "Define roles per application, attach permissions to them, and override access for an individual user."],
  ["Audit log", "Sign-ins, failures, password resets and key rotations are recorded and cannot be edited."],
  ["Developer console", "Create applications, copy keys, set allowed origins and token lifetimes, and manage end users."],
  ["Isolated by application", "Each application's users, roles and sessions are separated from every other application, enforced in the database."],
];

const steps = [
  ["Register an application", "Create it in the console, list the origins it will run on, and copy its publishable key."],
  ["Add the SDK to your app", "Mount one server route and place the sign-in components. Tokens stay in HttpOnly cookies and never reach browser JavaScript."],
  ["Manage users in the console", "Review users and sessions, assign roles, and rotate keys. Every change is written to the audit log."],
];

const security = [
  ["Passwords", "Stored as Argon2id hashes. Refresh and email tokens are kept only as SHA-256 hashes."],
  ["Tokens", "RS256-signed JWTs. Refresh tokens rotate on every use, and reuse of an old one revokes the session."],
  ["Browser storage", "Tokens live in HttpOnly cookies. The browser never reads an access or refresh token."],
  ["Abuse protection", "Per-IP rate limits, and a temporary lockout after repeated failed sign-ins."],
  ["Origin control", "Requests are accepted only from the origins you list for each application."],
  ["Transport", "HTTPS with HSTS. The database and the cache both require TLS."],
];

export function LandingPage() {
  return (
    <>
      <section className={styles.hero}>
        <div className={styles.container}>
          <div className={styles.heroGrid}>
            <div className={styles.heroText}>
              <h1>Authentication for the applications you build.</h1>
              <p className={styles.lead}>
                Auth Platform provides sign-up, sign-in, email verification, one-time-password MFA, session management, and roles
                and permissions as a hosted service, with a console to run all of it.
              </p>
              <div className={styles.ctas}>
                <Link className={styles.primary} href="/signup">Sign up</Link>
                <Link className={styles.secondary} href="/login">Sign in</Link>
                <Link className={styles.textLink} href="/docs">Read the documentation</Link>
              </div>
            </div>

            <div aria-label="Example integration" className={styles.code} role="group">
              <div className={styles.codeFile}>app/api/auth/[...path]/route.ts</div>
              <pre><code>{routeSnippet}</code></pre>
              <div className={styles.codeFile}>app/sign-in/page.tsx</div>
              <pre><code>{pageSnippet}</code></pre>
              <div className={styles.codeNote}>The SDK packages are not on npm yet. Installation instructions are coming soon.</div>
            </div>
          </div>
        </div>
      </section>

      <section className={styles.section} id="features">
        <div className={styles.container}>
          <div className={styles.split}>
            <div className={styles.sectionIntro}>
              <h2>What is included</h2>
              <p>Everything an application needs to know who its users are and what they may do, in one service.</p>
            </div>
            <dl className={styles.rows}>
              {features.map(([title, body]) => (
                <div className={styles.row} key={title}>
                  <dt>{title}</dt>
                  <dd>{body}</dd>
                </div>
              ))}
            </dl>
          </div>
        </div>
      </section>

      <section className={`${styles.section} ${styles.tinted}`} id="how-it-works">
        <div className={styles.container}>
          <div className={styles.sectionIntro}>
            <h2>How it works</h2>
          </div>
          <ol className={styles.steps}>
            {steps.map(([title, body], index) => (
              <li key={title}>
                <span className={styles.stepNumber}>{String(index + 1).padStart(2, "0")}</span>
                <h3>{title}</h3>
                <p>{body}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className={styles.section} id="architecture">
        <div className={styles.container}>
          <div className={`${styles.sectionIntro} ${styles.introWide}`}>
            <h2>Architecture</h2>
            <p>
              Auth Platform runs on AWS behind an HTTPS load balancer. The console and API share one instance, and the database and
              cache sit in a private subnet with no route to the internet.
            </p>
            <Link className={styles.textLink} href="/docs#how-it-works">Read how it works</Link>
          </div>
          <ArchitectureDiagram />
        </div>
      </section>

      <section className={`${styles.section} ${styles.tinted}`} id="security">
        <div className={styles.container}>
          <div className={styles.split}>
            <div className={styles.sectionIntro}>
              <h2>Security</h2>
              <p>The defaults are the ones you would otherwise have to remember to set.</p>
              <Link className={styles.textLink} href="/docs#security">Read the security model</Link>
            </div>
            <dl className={styles.rows}>
              {security.map(([title, body]) => (
                <div className={styles.row} key={title}>
                  <dt>{title}</dt>
                  <dd>{body}</dd>
                </div>
              ))}
            </dl>
          </div>
        </div>
      </section>

      <section className={styles.cta}>
        <div className={styles.container}>
          <div className={styles.ctaInner}>
            <div>
              <h2>Create a developer account</h2>
              <p>Register your first application and connect it to your app.</p>
            </div>
            <div className={styles.ctas}>
              <Link className={styles.ctaPrimary} href="/signup">Sign up</Link>
              <Link className={styles.ctaSecondary} href="/login">Sign in</Link>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}
