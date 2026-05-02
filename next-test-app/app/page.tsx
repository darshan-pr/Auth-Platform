"use client";

import { useAuth } from "auth-platform-sdk/client";
import { useEffect, useState } from "react";

export default function HomePage() {
  const { user, login, logout, isAuthenticated, loading, authClient, logoutReason } =
    useAuth();
  const [tokenPayload, setTokenPayload] = useState<Record<string, unknown> | null>(
    null,
  );
  const [timeUntilExpiry, setTimeUntilExpiry] = useState<number>(0);
  const [claimsLoading, setClaimsLoading] = useState(false);
  const fallbackClaims = {
    sub: user?.sub ?? null,
    email: user?.email ?? null,
    user_id: user?.user_id ?? null,
    app_id: user?.app_id ?? null,
    scope: user?.scope ?? null,
    iss: user?.issuer ?? null,
    iat: user?.issued_at ? Math.floor(user.issued_at.getTime() / 1000) : null,
    exp: user?.expires_at ? Math.floor(user.expires_at.getTime() / 1000) : null,
  };

  useEffect(() => {
    if (!isAuthenticated || !authClient) {
      return;
    }

    const intervalId = setInterval(() => {
      if (!user?.expires_at) {
        setTimeUntilExpiry(0);
        return;
      }
      const ttl = Math.max(
        0,
        Math.floor((user.expires_at.getTime() - Date.now()) / 1000),
      );
      setTimeUntilExpiry(ttl);
    }, 1000);

    return () => {
      clearInterval(intervalId);
    };
  }, [authClient, isAuthenticated, user]);

  const refreshClaims = async () => {
    if (!authClient) return;
    setClaimsLoading(true);
    try {
      const payload = await authClient.verifyToken();
      setTokenPayload(payload);
    } finally {
      setClaimsLoading(false);
    }
  };

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
        <button
          onClick={() => login()}
          className="rounded-md bg-black px-4 py-2 text-white"
        >
          Login via Auth Platform
        </button>
      </main>
    );
  }

  return (
    <main className="mx-auto flex min-h-screen w-full max-w-4xl flex-col gap-6 p-6">
      <h1 className="text-2xl font-semibold">Auth Session Details</h1>

      <div className="rounded-lg border p-4">
        <h2 className="mb-3 text-lg font-medium">User</h2>
        <div className="grid gap-2 text-sm">
          <p>
            <strong>Email:</strong> {user?.email ?? "N/A"}
          </p>
          <p>
            <strong>Subject (sub):</strong> {user?.sub ?? "N/A"}
          </p>
          <p>
            <strong>User ID:</strong> {user?.user_id ?? "N/A"}
          </p>
          <p>
            <strong>App ID:</strong> {user?.app_id ?? "N/A"}
          </p>
          <p>
            <strong>Issuer:</strong> {user?.issuer ?? "N/A"}
          </p>
          <p>
            <strong>Scope:</strong> {user?.scope ?? "N/A"}
          </p>
          <p>
            <strong>Issued At:</strong>{" "}
            {user?.issued_at ? user.issued_at.toISOString() : "N/A"}
          </p>
          <p>
            <strong>Expires At:</strong>{" "}
            {user?.expires_at ? user.expires_at.toISOString() : "N/A"}
          </p>
          <p>
            <strong>Time Until Expiry:</strong> {timeUntilExpiry}s
          </p>
          <p>
            <strong>Authenticated:</strong> {isAuthenticated ? "Yes" : "No"}
          </p>
          <p>
            <strong>Logout Reason:</strong> {logoutReason ?? "N/A"}
          </p>
          <p>
            <strong>Access Token:</strong> HttpOnly cookie (not readable in
            browser)
          </p>
        </div>
      </div>

      <div className="rounded-lg border p-4">
        <div className="mb-3 flex items-center justify-between gap-3">
          <h2 className="text-lg font-medium">Raw Token Claims</h2>
          <button
            onClick={refreshClaims}
            disabled={claimsLoading}
            className="rounded-md border px-3 py-1.5 text-sm disabled:opacity-60"
          >
            {claimsLoading ? "Refreshing..." : "Refresh from server"}
          </button>
        </div>
        <pre className="overflow-x-auto rounded bg-neutral-100 p-3 text-xs text-neutral-900 dark:bg-neutral-900 dark:text-neutral-100">
          {JSON.stringify(tokenPayload ?? fallbackClaims, null, 2)}
        </pre>
      </div>

      <button onClick={logout} className="w-fit rounded-md border px-4 py-2">
        Sign Out
      </button>
    </main>
  );
}
