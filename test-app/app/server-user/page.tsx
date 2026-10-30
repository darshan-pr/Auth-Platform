import Link from "next/link";
import { connection } from "next/server";
import { Suspense } from "react";
import { currentUser } from "@authplatform/auth-nextjs";

export const instant = false;

export default function ServerUserPage() {
  return <main className="test-shell"><h1>Server currentUser()</h1><Suspense fallback={<p role="status">Loading server session…</p>}><ServerUser /></Suspense><Link href="/protected">Back to protected page</Link></main>;
}

async function ServerUser() {
  await connection();
  const user = await currentUser();
  return user ? <pre>{JSON.stringify(user, null, 2)}</pre> : <p>No authenticated server session.</p>;
}
