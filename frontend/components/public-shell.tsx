import Link from "next/link";
import type { ReactNode } from "react";
import styles from "./public-shell.module.css";

export function PublicShell({ children }: { children: ReactNode }) {
  return (
    <div className={styles.page}>
      <a className={styles.skip} href="#main">Skip to content</a>
      <header className={styles.header}>
        <div className={styles.headerInner}>
          <Link aria-label="Auth Platform home" className={styles.brand} href="/">
            <img alt="" className={styles.logo} src="/auth-platform-icon-black.png" />
            <span>Auth<span className={styles.accent}> Platform</span></span>
          </Link>
          <nav aria-label="Primary" className={styles.nav}>
            <Link href="/#features">Features</Link>
            <Link href="/#architecture">Architecture</Link>
            <Link href="/#security">Security</Link>
            <Link href="/docs">Documentation</Link>
          </nav>
          <div className={styles.actions}>
            <Link className={styles.signIn} href="/login">Sign in</Link>
            <Link className={styles.signUp} href="/signup">Sign up</Link>
          </div>
        </div>
      </header>
      <main id="main">{children}</main>
      <footer className={styles.footer}>
        <div className={styles.footerInner}>
          <div>
            <div className={styles.footerBrand}>Auth Platform</div>
            <p>Authentication, sessions and permissions for the applications you build.</p>
          </div>
          <nav aria-label="Footer" className={styles.footerLinks}>
            <Link href="/docs">Documentation</Link>
            <Link href="/login">Sign in</Link>
            <Link href="/signup">Sign up</Link>
            <Link href="/sa/login">Platform administration</Link>
          </nav>
        </div>
      </footer>
    </div>
  );
}
