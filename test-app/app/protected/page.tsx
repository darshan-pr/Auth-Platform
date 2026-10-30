"use client";

import Link from "next/link";
import { AuthProvider, UserButton, useAuth } from "@authplatform/auth-react";

function ProtectedContent() {
  const { isLoaded, isSignedIn, user, snapshot, retrySession } = useAuth();
  return <main className="test-shell"><h1>Protected page</h1>{snapshot.status === "error" ? <div role="alert"><p>{snapshot.error}</p><button onClick={() => void retrySession()} type="button">Retry session check</button></div> : !isLoaded ? <p role="status">Loading session…</p> : isSignedIn && user ? <><p>Signed in as {user.email}</p><UserButton /></> : <p>Session unavailable.</p>}<Link href="/server-user">View server current user</Link></main>;
}

export default function ProtectedPage() {
  return <AuthProvider><ProtectedContent /></AuthProvider>;
}
