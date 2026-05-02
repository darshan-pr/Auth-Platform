"use client";

import { useAuth } from "auth-platform-sdk/client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

export default function AuthCallbackPage() {
  const router = useRouter();
  const { isAuthenticated, loading } = useAuth();

  useEffect(() => {
    if (!loading && isAuthenticated) {
      router.replace("/");
    }
  }, [isAuthenticated, loading, router]);

  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-4">
      {loading ? (
        <p>Completing sign in...</p>
      ) : (
        <>
          <p>Sign in could not be completed.</p>
          <Link href="/" className="rounded-md border border-black px-4 py-2">
            Go Home
          </Link>
        </>
      )}
    </main>
  );
}
