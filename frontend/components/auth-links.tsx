"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import { useSessionState } from "../lib/use-session-state";

type Classes = { signIn?: string; signUp?: string; console?: string; sa?: string };

/**
 * Sign in / Sign up links for visitors, or shortcuts into the console for people who are already
 * signed in. Space is reserved while the session check runs so the page does not jump.
 */
export function AuthLinks({ classes = {}, signUpFirst = false }: { classes?: Classes; signUpFirst?: boolean }) {
  const session = useSessionState();
  const signedIn = Boolean(session?.console || session?.sa);
  const signIn = <Link className={classes.signIn} href="/login" key="in">Sign in</Link>;
  const signUp = <Link className={classes.signUp} href="/signup" key="up">Sign up</Link>;
  if (!session) return <span aria-hidden="true" style={{ display: "contents", visibility: "hidden" }}>{signUpFirst ? <>{signUp}{signIn}</> : <>{signIn}{signUp}</>}</span>;
  if (!signedIn) return signUpFirst ? <>{signUp}{signIn}</> : <>{signIn}{signUp}</>;
  return <>
    {session.sa && <Link className={classes.sa ?? classes.signIn} href="/overview">Administration</Link>}
    {session.console && <Link className={classes.console ?? classes.signUp} href="/console/overview">Open console</Link>}
  </>;
}

/** Plain footer links with the same signed-in behaviour. */
export function FooterAuthLinks() {
  const session = useSessionState();
  if (session?.console || session?.sa) {
    return <>
      {session.console && <Link href="/console/overview">Developer console</Link>}
      {session.sa && <Link href="/overview">Platform administration</Link>}
    </>;
  }
  return <>
    <Link href="/login">Sign in</Link>
    <Link href="/signup">Sign up</Link>
    <Link href="/sa/login">Platform administration</Link>
  </>;
}

/** Hides its children once the visitor is known to be signed in. */
export function SignedOutOnly({ children }: { children: ReactNode }) {
  const session = useSessionState();
  return session?.console || session?.sa ? null : <>{children}</>;
}
