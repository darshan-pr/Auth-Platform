import type { Metadata } from "next";
import Link from "next/link";
import { UserButton } from "@authplatform/auth-react";

export const metadata: Metadata = {
  title: "SDK test app",
};

export default function HomePage() {
  return <main className="test-shell"><h1>Auth Platform SDK</h1><p>Workspace package App Router integration.</p><UserButton /><nav aria-label="Authentication navigation"><Link href="/sign-in">Sign in</Link><Link href="/sign-up">Sign up</Link><Link href="/protected">Protected page</Link><Link href="/permissions">Permission checks</Link><Link href="/server-user">Server current user</Link></nav></main>;
}
