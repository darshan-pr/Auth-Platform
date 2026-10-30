import assert from "node:assert/strict";
import test from "node:test";
import { AuthClient, AuthError, AuthSessionState, validateSignup } from "../src/index.ts";

test("validates signup input without making a request", () => {
  assert.deepEqual(validateSignup({ name: "", email: "bad", password: "short" }), {
    name: "Enter your name.",
    email: "Enter a valid email address.",
    password: "Password must be 10-128 characters and contain a letter and a number."
  });
});

test("normalizes backend errors without exposing backend messages", async () => {
  const client = new AuthClient({
    fetch: async () => new Response(JSON.stringify({ error: { code: "INVALID_CREDENTIALS", message: "database detail", requestId: "req-1" } }), { status: 401 })
  });
  await assert.rejects(() => client.signIn({ email: "user@example.com", password: "password1234" }), (error: unknown) => {
    assert.ok(error instanceof AuthError);
    assert.equal(error.code, "INVALID_CREDENTIALS");
    assert.equal(error.message, "Email or password is incorrect.");
    assert.equal(error.requestId, "req-1");
    return true;
  });
});

test("loads application branding through the same-origin BFF", async () => {
  let requestUrl = "";
  const client = new AuthClient({
    fetch: async (input) => {
      requestUrl = String(input);
      return new Response(JSON.stringify({
        name: "Demo app",
        iconUrl: null,
        iconDataUrl: "data:image/webp;base64,UklGRg==",
        iconPositionX: 50,
        iconPositionY: 50,
        iconZoomPercent: 100
      }));
    }
  });

  assert.deepEqual(await client.getApplicationBranding(), {
    name: "Demo app",
    iconUrl: null,
    iconDataUrl: "data:image/webp;base64,UklGRg==",
    iconPositionX: 50,
    iconPositionY: 50,
    iconZoomPercent: 100
  });
  assert.equal(requestUrl, "/api/auth/application");
});

test("session state publishes transitions and supports unsubscribe", () => {
  const state = new AuthSessionState();
  const snapshots: string[] = [];
  const unsubscribe = state.subscribe((snapshot) => snapshots.push(snapshot.status));
  state.set({ status: "unauthenticated", user: null });
  unsubscribe();
  state.set({ status: "authenticated", user: { id: "u1", name: "User", email: "user@example.com", emailVerified: true, roles: [], permissions: [] } });
  assert.deepEqual(snapshots, ["unauthenticated"]);
  assert.equal(state.value.status, "authenticated");
});

test("MFA login and OTP password recovery use BFF-only challenge requests", async () => {
  const requests: Array<{ path: string; body: string | undefined; csrf: string | null }> = [];
  const challenge = { challengeId: "challenge-1", expiresIn: 300, message: "Check your email." };
  const user = {
    id: "u1",
    name: "User",
    email: "user@example.com",
    emailVerified: true,
    roles: [],
    permissions: []
  };
  const client = new AuthClient({
    csrfToken: () => "csrf-token",
    fetch: async (input, init) => {
      const url = new URL(String(input), "http://localhost");
      requests.push({
        path: url.pathname,
        body: typeof init?.body === "string" ? init.body : undefined,
        csrf: new Headers(init?.headers).get("X-Authplatform-CSRF")
      });
      if (url.pathname.endsWith("/login")) {
        return new Response(JSON.stringify({
          authenticated: false,
          otpRequired: true,
          user,
          ...challenge
        }), { status: 202 });
      }
      if (url.pathname.endsWith("/login/otp")) {
        return new Response(JSON.stringify({
          authenticated: true,
          otpRequired: false,
          user,
          expiresIn: 900
        }));
      }
      if (url.pathname.endsWith("/forgot-password/otp")) {
        return new Response(JSON.stringify(challenge), { status: 202 });
      }
      if (url.pathname.endsWith("/forgot-password/otp/resend")) {
        return new Response(JSON.stringify(challenge), { status: 202 });
      }
      return new Response(JSON.stringify({ message: "Password reset successfully" }));
    }
  });

  const login = await client.signIn({ email: user.email, password: "StrongPassword123" });
  assert.equal(login.authenticated, false);
  assert.equal(login.otpRequired, true);
  assert.equal(login.user, null);
  assert.equal(login.challengeId, challenge.challengeId);

  const verified = await client.verifyOtp(challenge.challengeId, "123456");
  assert.equal(verified.authenticated, true);
  assert.equal(verified.user?.id, user.id);

  const reset = await client.startPasswordReset(user.email);
  await client.resendPasswordResetOtp(reset.challengeId);
  const result = await client.resetPasswordWithOtp(reset.challengeId, "123456", "NewPassword123");
  assert.equal(result.message, "Password reset successfully");
  assert.deepEqual(requests.map(({ path }) => path), [
    "/api/auth/login",
    "/api/auth/login/otp",
    "/api/auth/forgot-password/otp",
    "/api/auth/forgot-password/otp/resend",
    "/api/auth/reset-password/otp"
  ]);
  assert.ok(requests.every((request) => request.csrf === "csrf-token"));
  assert.ok(requests.every((request) => request.path.startsWith("/api/auth/")));
});

test("email verification submits its token through the same-origin BFF", async () => {
  let requestPath = "";
  let requestBody = "";
  const client = new AuthClient({
    csrfToken: () => "csrf-token",
    fetch: async (input, init) => {
      requestPath = new URL(String(input), "http://localhost").pathname;
      requestBody = String(init?.body);
      return new Response(JSON.stringify({ emailVerified: true }));
    }
  });

  const result = await client.verifyEmail("verification-token");

  assert.equal(result.emailVerified, true);
  assert.equal(requestPath, "/api/auth/verify-email");
  assert.deepEqual(JSON.parse(requestBody), { token: "verification-token" });
});

test("session management uses the authenticated BFF and never sends tokens to the client", async () => {
  const requests: Array<{ path: string; method: string; csrf: string | null }> = [];
  const client = new AuthClient({
    csrfToken: () => "csrf-token",
    fetch: async (input, init) => {
      const url = new URL(String(input), "http://localhost");
      requests.push({
        path: url.pathname,
        method: init?.method ?? "GET",
        csrf: new Headers(init?.headers).get("X-Authplatform-CSRF")
      });
      if (url.pathname.endsWith("/sessions")) {
        return new Response(JSON.stringify([{
          id: "session-1",
          ipAddress: "127.0.0.1",
          userAgent: "Browser",
          createdAt: "2026-10-22T00:00:00Z",
          lastActiveAt: "2026-10-22T00:00:00Z",
          expiresAt: "2026-10-23T00:00:00Z",
          current: true
        }]));
      }
      return new Response(null, { status: 204 });
    }
  });

  const sessions = await client.getSessions();
  await client.revokeSession("session-1");

  assert.equal(sessions.length, 1);
  assert.equal(sessions[0]?.current, true);
  assert.deepEqual(requests, [
    { path: "/api/auth/sessions", method: "GET", csrf: null },
    { path: "/api/auth/sessions/session-1", method: "DELETE", csrf: "csrf-token" }
  ]);
});

test("refreshes an expired app-user access token before loading the user", async () => {
  const requests: string[] = [];
  const user = {
    id: "u1",
    name: "User",
    email: "user@example.com",
    emailVerified: true,
    roles: ["member"],
    permissions: []
  };
  const client = new AuthClient({
    csrfToken: () => "csrf-token",
    fetch: async (input) => {
      const path = new URL(String(input), "http://localhost").pathname;
      requests.push(path);
      if (path === "/api/auth/me" && requests.filter((item) => item === path).length === 1) {
        return new Response(JSON.stringify({ error: { code: "UNAUTHENTICATED" } }), { status: 401 });
      }
      if (path === "/api/auth/refresh") {
        return new Response(JSON.stringify({ authenticated: true, otpRequired: false, user, expiresIn: 900 }));
      }
      return new Response(JSON.stringify(user));
    }
  });

  assert.deepEqual(await client.getUser(), user);
  assert.deepEqual(requests, ["/api/auth/me", "/api/auth/refresh", "/api/auth/me"]);
});

test("an invalid refresh session leaves the SDK unauthenticated", async () => {
  const requests: string[] = [];
  const client = new AuthClient({
    csrfToken: () => "csrf-token",
    fetch: async (input) => {
      const path = new URL(String(input), "http://localhost").pathname;
      requests.push(path);
      return new Response(
        JSON.stringify({ error: { code: path.endsWith("/refresh") ? "TOKEN_INVALID" : "UNAUTHENTICATED" } }),
        { status: path.endsWith("/refresh") ? 400 : 401 }
      );
    }
  });

  assert.equal(await client.getUser(), null);
  assert.deepEqual(requests, ["/api/auth/me", "/api/auth/refresh"]);
});

test("retries protected SDK requests after a successful refresh", async () => {
  const requests: string[] = [];
  const client = new AuthClient({
    csrfToken: () => "csrf-token",
    fetch: async (input) => {
      const path = new URL(String(input), "http://localhost").pathname;
      requests.push(path);
      if (path === "/api/auth/sessions" && requests.filter((item) => item === path).length === 1) {
        return new Response(JSON.stringify({ error: { code: "UNAUTHENTICATED" } }), { status: 401 });
      }
      if (path === "/api/auth/refresh") {
        return new Response(JSON.stringify({
          authenticated: true,
          otpRequired: false,
          user: {
            id: "u1",
            name: "User",
            email: "user@example.com",
            emailVerified: true,
            roles: [],
            permissions: []
          },
          expiresIn: 900
        }));
      }
      return new Response(JSON.stringify([]));
    }
  });

  assert.deepEqual(await client.getSessions(), []);
  assert.deepEqual(requests, ["/api/auth/sessions", "/api/auth/refresh", "/api/auth/sessions"]);
});

test("shares one refresh request across simultaneous protected SDK requests", async () => {
  const requests: string[] = [];
  let refreshed = false;
  let refreshCalls = 0;
  const user = {
    id: "u1",
    name: "User",
    email: "user@example.com",
    emailVerified: true,
    roles: ["member"],
    permissions: []
  };
  const client = new AuthClient({
    csrfToken: () => "csrf-token",
    fetch: async (input) => {
      const path = new URL(String(input), "http://localhost").pathname;
      requests.push(path);
      if (path === "/api/auth/refresh") {
        refreshCalls += 1;
        await new Promise((resolve) => setTimeout(resolve, 5));
        refreshed = true;
        return new Response(JSON.stringify({ authenticated: true, user, expiresIn: 300, refreshExpiresIn: 3600 }));
      }
      if (!refreshed) {
        return new Response(JSON.stringify({ error: { code: "UNAUTHENTICATED" } }), { status: 401 });
      }
      return new Response(JSON.stringify(user));
    }
  });

  const results = await Promise.all([client.getUser(), client.getUser()]);

  assert.deepEqual(results, [user, user]);
  assert.equal(refreshCalls, 1);
  assert.equal(requests.filter((path) => path === "/api/auth/me").length, 4);
});

test("retries a refresh that conflicts with another tab's rotation", async () => {
  let refreshCalls = 0;
  const client = new AuthClient({
    csrfToken: () => "csrf-token",
    fetch: async () => {
      refreshCalls += 1;
      if (refreshCalls === 1) {
        return new Response(JSON.stringify({ error: { code: "REFRESH_IN_PROGRESS" } }), {
          status: 409
        });
      }
      return new Response(JSON.stringify({ authenticated: true, expiresIn: 900 }));
    }
  });

  assert.equal((await client.refresh()).authenticated, true);
  assert.equal(refreshCalls, 2);
});

test("serializes refresh requests from separate SDK clients with browser locks", async () => {
  const originalNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const queues = new Map<string, Promise<void>>();
  const lockManager = {
    request<T>(name: string, callback: () => Promise<T>): Promise<T> {
      const previous = queues.get(name) ?? Promise.resolve();
      let release!: () => void;
      const lock = new Promise<void>((resolve) => {
        release = resolve;
      });
      const tail = previous.then(() => lock);
      queues.set(name, tail);
      return previous.then(callback).finally(() => {
        release();
        if (queues.get(name) === tail) queues.delete(name);
      });
    }
  };
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { locks: lockManager }
  });

  let activeRefreshes = 0;
  let maximumConcurrentRefreshes = 0;
  const makeClient = () =>
    new AuthClient({
      csrfToken: () => "csrf-token",
      fetch: async (input) => {
        if (new URL(String(input), "http://localhost").pathname !== "/api/auth/refresh") {
          throw new Error("Unexpected request");
        }
        activeRefreshes += 1;
        maximumConcurrentRefreshes = Math.max(maximumConcurrentRefreshes, activeRefreshes);
        await new Promise((resolve) => setTimeout(resolve, 5));
        activeRefreshes -= 1;
        return new Response(JSON.stringify({ authenticated: true, expiresIn: 900 }));
      }
    });

  try {
    await Promise.all([makeClient().refresh(), makeClient().refresh()]);
    assert.equal(maximumConcurrentRefreshes, 1);
  } finally {
    if (originalNavigator) {
      Object.defineProperty(globalThis, "navigator", originalNavigator);
    } else {
      Reflect.deleteProperty(globalThis, "navigator");
    }
  }
});
