import test from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server.js";
import { createAuthHandlers } from "../dist/esm/handlers.js";

function refreshRequest(): NextRequest {
  return new NextRequest("http://localhost:3001/api/auth/refresh", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      cookie: "authplatform_sdk_refresh=refresh-token; authplatform_csrf=csrf-token",
      origin: "http://localhost:3001",
      "x-authplatform-csrf": "csrf-token"
    },
    body: "{}"
  });
}

async function postRefresh() {
  const handlers = createAuthHandlers({
    backendUrl: "http://backend.local",
    publishableKey: "pk_test"
  });
  return handlers.POST(refreshRequest(), {
    params: Promise.resolve({ path: ["refresh"] })
  });
}

test("refresh preserves auth cookies when the backend is temporarily unreachable", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("backend unavailable");
  };
  try {
    const response = await postRefresh();

    assert.equal(response.status, 502);
    assert.deepEqual(response.cookies.getAll(), []);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("refresh preserves auth cookies on transient backend errors", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ error: { code: "INTERNAL_ERROR" } }), {
      status: 503,
      headers: { "content-type": "application/json" }
    });
  try {
    const response = await postRefresh();

    assert.equal(response.status, 503);
    assert.deepEqual(response.cookies.getAll(), []);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("refresh preserves auth cookies when another request just rotated the token", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ error: { code: "REFRESH_IN_PROGRESS" } }), {
      status: 409,
      headers: { "content-type": "application/json" }
    });
  try {
    const response = await postRefresh();

    assert.equal(response.status, 409);
    assert.deepEqual(response.cookies.getAll(), []);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("refresh clears auth cookies when the refresh session is invalid", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ error: { code: "TOKEN_INVALID" } }), {
      status: 400,
      headers: { "content-type": "application/json" }
    });
  try {
    const response = await postRefresh();
    const expiredCookies = response.cookies.getAll().filter((cookie) => cookie.maxAge === 0);

    assert.equal(response.status, 400);
    assert.ok(expiredCookies.some((cookie) => cookie.name.endsWith("authplatform_sdk_refresh")));
    assert.ok(expiredCookies.some((cookie) => cookie.name.endsWith("authplatform_sdk_access")));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
