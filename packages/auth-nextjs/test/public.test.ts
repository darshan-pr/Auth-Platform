import test from "node:test";
import assert from "node:assert/strict";
import { publicLogin, publicSuccess } from "../src/public.ts";

test("public login output allowlists user fields and never returns tokens", () => {
  const output = publicLogin({
    accessToken: "access-secret",
    refreshToken: "refresh-secret",
    expiresIn: 900,
    refreshExpiresIn: 7200,
    user: { id: "u1", email: "user@example.com", roles: ["member"], passwordHash: "secret" },
    internalTrace: "database details"
  });

  assert.deepEqual(output, {
    authenticated: true,
    user: { id: "u1", name: "", email: "user@example.com", emailVerified: false, roles: ["member"], permissions: [] },
    otpRequired: false,
    expiresIn: 900,
    refreshExpiresIn: 7200
  });
});

test("public success output does not forward upstream fields", () => {
  assert.deepEqual(publicSuccess("forgot-password", { message: "different internal message", emailExists: true }), {
    message: "If the account exists, an email has been sent"
  });
  assert.deepEqual(publicSuccess("signup", { id: "u1", email: "user@example.com", passwordHash: "secret" }), {
    id: "u1",
    email: "user@example.com",
    emailVerified: false,
    message: "Account created. Please verify your email."
  });
  assert.deepEqual(publicSuccess("verify-email", { emailVerified: true, internalToken: "secret" }), {
    emailVerified: true
  });
});

test("public session output contains only safe session metadata", () => {
  assert.deepEqual(publicSuccess("sessions", [{
    id: "session-1",
    ipAddress: "127.0.0.1",
    userAgent: "Browser",
    createdAt: "2026-10-22T00:00:00Z",
    lastActiveAt: "2026-10-22T00:00:00Z",
    expiresAt: "2026-10-23T00:00:00Z",
    current: true,
    refreshTokenHash: "never-forward-this",
    accountId: "private"
  }]), [{
    id: "session-1",
    ipAddress: "127.0.0.1",
    userAgent: "Browser",
    createdAt: "2026-10-22T00:00:00Z",
    lastActiveAt: "2026-10-22T00:00:00Z",
    expiresAt: "2026-10-23T00:00:00Z",
    current: true
  }]);
});

test("public application branding forwards only validated branding fields", () => {
  const icon = `data:image/png;base64,${"A".repeat(128)}`;
  assert.deepEqual(publicSuccess("application", {
    name: "  Demo app  ",
    iconUrl: "https://cdn.example.com/icon.png",
    iconDataUrl: icon,
    iconPositionX: 24,
    iconPositionY: 72,
    iconZoomPercent: 160,
    publishableKey: "private-extra-field"
  }), {
    name: "Demo app",
    iconUrl: "https://cdn.example.com/icon.png",
    iconDataUrl: icon,
    iconPositionX: 24,
    iconPositionY: 72,
    iconZoomPercent: 160
  });

  assert.deepEqual(publicSuccess("application", {
    name: "App",
    iconUrl: "javascript:alert(1)",
    iconDataUrl: "data:image/svg+xml;base64,PHN2Zy8+",
    iconPositionX: 101,
    iconPositionY: -1,
    iconZoomPercent: 999
  }), {
    name: "App",
    iconUrl: null,
    iconDataUrl: null,
    iconPositionX: 50,
    iconPositionY: 50,
    iconZoomPercent: 100
  });
});

test("MFA login stays a challenge and password-reset OTP keeps only challenge metadata", () => {
  const login = publicLogin({
    accessToken: null,
    refreshToken: null,
    otpRequired: true,
    challengeId: "challenge-1",
    expiresIn: 300,
    user: { id: "u1", email: "user@example.com", passwordHash: "secret" }
  });
  assert.deepEqual(login, {
    authenticated: false,
    otpRequired: true,
    challengeId: "challenge-1",
    expiresIn: 300
  });

  assert.deepEqual(
    publicSuccess("forgot-password/otp", {
      challengeId: "challenge-2",
      expiresIn: 300,
      message: "internal detail",
      emailExists: true
    }),
    {
      message: "If the account exists, a one-time password was sent to its email address.",
      challengeId: "challenge-2",
      expiresIn: 300
    }
  );
});
