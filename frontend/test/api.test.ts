import test from "node:test";
import assert from "node:assert/strict";
import { ApiError, apiFetch } from "../lib/api.ts";

test("refreshes an expired console access token and retries the request", async () => {
  const originalFetch = globalThis.fetch;
  const requests: string[] = [];
  let protectedRequests = 0;
  let refreshAttempts = 0;
  globalThis.fetch = async (input) => {
    const path = new URL(String(input)).pathname;
    requests.push(path);
    if (path === "/api/sa/auth/refresh") {
      refreshAttempts += 1;
      if (refreshAttempts === 1) {
        return new Response(JSON.stringify({ error: { code: "REFRESH_IN_PROGRESS" } }), {
          status: 409,
          headers: { "content-type": "application/json" }
        });
      }
      return new Response(null, { status: 204 });
    }
    protectedRequests += 1;
    if (protectedRequests === 1) {
      return new Response(JSON.stringify({ error: { code: "UNAUTHENTICATED" } }), {
        status: 401,
        headers: { "content-type": "application/json" }
      });
    }
    return new Response(JSON.stringify({ status: "ok" }));
  };
  try {
    assert.deepEqual(await apiFetch("/api/sa/analytics/overview"), { status: "ok" });
    assert.deepEqual(requests, [
      "/api/sa/analytics/overview",
      "/api/sa/auth/refresh",
      "/api/sa/auth/refresh",
      "/api/sa/analytics/overview"
    ]);
    assert.equal(refreshAttempts, 2);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("does not turn a transient refresh failure into an unauthenticated response", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const path = new URL(String(input)).pathname;
    if (path === "/api/sa/auth/refresh") {
      return new Response(JSON.stringify({ error: { code: "INTERNAL_ERROR", message: "Temporarily unavailable." } }), {
        status: 503,
        headers: { "content-type": "application/json" }
      });
    }
    return new Response(JSON.stringify({ error: { code: "UNAUTHENTICATED" } }), {
      status: 401,
      headers: { "content-type": "application/json" }
    });
  };
  try {
    await assert.rejects(
      () => apiFetch("/api/sa/analytics/overview"),
      (error: unknown) => error instanceof ApiError && error.status === 503
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});
