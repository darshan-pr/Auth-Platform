"use client";

import { useAuth } from "auth-platform-sdk/client";

export default function HomePage() {
  const { user, login, logout, isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <main className="flex min-h-screen items-center justify-center">
        <p>Loading auth...</p>
      </main>
    );
  }

  if (!isAuthenticated) {
    return (
      <main className="flex min-h-screen flex-col items-center justify-center gap-4">
        <h1 className="text-2xl font-semibold">Next Test Auth App</h1>
        <p>
          Install SDK with <code>npm install auth-platform-sdk</code>
        </p>
        <button
          onClick={() => login()}
          className="rounded-md bg-black px-4 py-2 text-white"
        >
          Sign In
        </button>
      </main>
    );
  }

  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-4">
      <h1 className="text-2xl font-semibold">You are logged in</h1>
      <p>{user?.email ?? "No email available"}</p>
      <button
        onClick={logout}
        className="rounded-md border border-black px-4 py-2"
      >
        Sign Out
      </button>
    </main>
  );
}
