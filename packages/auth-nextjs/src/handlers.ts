import "server-only";

import { NextRequest, NextResponse } from "next/server.js";
import type { AuthErrorCode } from "@authplatform/auth-core";
import { AuthNextOptions, AuthConfig, CSRF_COOKIE, cookieNames, isSecureRequest, resolveConfig } from "./config.js";
import { publicLogin, publicSuccess } from "./public.js";

type RouteContext = { params: Promise<{ path?: string[] }> };
type Handler = (request: NextRequest, context: RouteContext) => Promise<NextResponse>;

const ALLOWED_PATHS = new Set([
  "csrf", "signup", "login", "login/otp", "login/otp/resend", "refresh", "logout",
  "verify-email", "resend-verification", "forgot-password", "forgot-password/otp",
  "forgot-password/otp/resend", "reset-password", "reset-password/otp", "me", "mfa/status",
  "sessions", "application"
]);
const MUTATING = new Set([
  "signup", "login", "login/otp", "login/otp/resend", "refresh", "logout", "verify-email",
  "resend-verification", "forgot-password", "forgot-password/otp",
  "forgot-password/otp/resend", "reset-password", "reset-password/otp"
]);
const TOKEN_RESPONSES = new Set(["login", "login/otp", "refresh"]);
const TERMINAL_REFRESH_ERRORS = new Set<AuthErrorCode>([
  "TOKEN_INVALID",
  "UNAUTHENTICATED",
  "USER_BLOCKED",
  "ACCOUNT_LOCKED"
]);

const PUBLIC_MESSAGES: Record<AuthErrorCode, string> = {
  VALIDATION_FAILED: "Please check the submitted fields.", INVALID_CREDENTIALS: "Email or password is incorrect.",
  EMAIL_TAKEN: "Unable to create an account with those details.", RATE_LIMITED: "Too many attempts. Please try again later.",
  RATE_LIMIT_UNAVAILABLE: "Authentication is temporarily unavailable.", ACCOUNT_LOCKED: "Sign-in is temporarily unavailable.",
  MFA_REQUIRED: "A verification code is required.", MFA_INVALID: "The verification code is invalid.",
  OTP_EXPIRED: "The verification code has expired.", TOKEN_INVALID: "That link or session is no longer valid.",
  EMAIL_NOT_VERIFIED: "Please verify your email before signing in.", USER_BLOCKED: "This account cannot sign in.",
  UNAUTHENTICATED: "Your session has expired. Please sign in again.",
  REFRESH_IN_PROGRESS: "Your session is still refreshing. Please retry in a moment.",
  ACCESS_DENIED: "You do not have access to this resource.", UNKNOWN_ERROR: "Authentication request failed."
};

function json(status: number, body: unknown, headers?: HeadersInit): NextResponse {
  const response = NextResponse.json(body, { status, headers });
  response.headers.set("Cache-Control", "no-store");
  return response;
}

function noContent(): NextResponse {
  const response = new NextResponse(null, { status: 204 });
  response.headers.set("Cache-Control", "no-store");
  return response;
}

function publicError(status: number, code: AuthErrorCode = "UNKNOWN_ERROR", requestId?: string) {
  return json(status, { error: { code, message: PUBLIC_MESSAGES[code], requestId } });
}

function codeFromUpstream(value: unknown): AuthErrorCode {
  const codes: AuthErrorCode[] = ["VALIDATION_FAILED", "INVALID_CREDENTIALS", "EMAIL_TAKEN", "RATE_LIMITED", "RATE_LIMIT_UNAVAILABLE", "ACCOUNT_LOCKED", "MFA_REQUIRED", "MFA_INVALID", "OTP_EXPIRED", "TOKEN_INVALID", "EMAIL_NOT_VERIFIED", "USER_BLOCKED", "UNAUTHENTICATED", "REFRESH_IN_PROGRESS", "ACCESS_DENIED"];
  return typeof value === "string" && codes.includes(value as AuthErrorCode) ? value as AuthErrorCode : "UNKNOWN_ERROR";
}

function sameValue(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

function originAllowed(request: NextRequest, config: AuthConfig): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  return origin === (config.allowedOrigin ?? request.nextUrl.origin);
}

function csrfValid(request: NextRequest, config: AuthConfig): boolean {
  if (!originAllowed(request, config)) return false;
  const cookie = request.cookies.get(CSRF_COOKIE)?.value;
  const header = request.headers.get("x-authplatform-csrf");
  return Boolean(cookie && header && sameValue(cookie, header));
}

function tokenMaxAge(token: string, fallback: number): number {
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8")) as { exp?: number };
    return typeof payload.exp === "number" ? Math.max(0, Math.floor(payload.exp - Date.now() / 1000)) : fallback;
  } catch { return fallback; }
}

function csrfValue(): string {
  return `${crypto.randomUUID()}${crypto.randomUUID()}`;
}

function setAuthCookies(
  response: NextResponse,
  request: NextRequest,
  accessToken?: string,
  refreshToken?: string,
  refreshExpiresIn?: number
): void {
  const secure = isSecureRequest(request.url);
  const names = cookieNames(secure);
  const common = { httpOnly: true, secure, sameSite: "lax" as const, path: "/" };
  if (accessToken) response.cookies.set(names.access, accessToken, { ...common, maxAge: tokenMaxAge(accessToken, 900) });
  if (refreshToken) {
    response.cookies.set(names.refresh, refreshToken, {
      ...common,
      maxAge: refreshExpiresIn ?? tokenMaxAge(refreshToken, 2_592_000)
    });
  }
}

function clearAuthCookies(response: NextResponse, request: NextRequest): void {
  const secure = isSecureRequest(request.url);
  const names = cookieNames(secure);
  for (const name of [names.access, names.refresh]) response.cookies.set(name, "", { httpOnly: true, secure, sameSite: "lax", path: "/", maxAge: 0 });
}

function backendPath(path: string): string {
  if (path === "me") return "/api/v1/users/me";
  if (path === "mfa/status") return "/api/v1/auth/mfa/status";
  if (path === "sessions") return "/api/v1/users/me/sessions";
  if (path.startsWith("sessions/")) return `/api/v1/users/me/${path}`;
  return `/api/v1/auth/${path}`;
}

async function upstream(request: NextRequest, config: AuthConfig, path: string): Promise<Response> {
  const secure = isSecureRequest(request.url);
  const names = cookieNames(secure);
  const accessToken = request.cookies.get(names.access)?.value;
  const refreshToken = request.cookies.get(names.refresh)?.value;
  const headers = new Headers({ Accept: "application/json", "X-authplatform-Key": config.publishableKey });
  if (accessToken && (path === "me" || path === "mfa/status" || path.startsWith("sessions"))) headers.set("Authorization", `Bearer ${accessToken}`);
  if (request.method !== "GET") headers.set("Content-Type", "application/json");
  let body: string | undefined;
  if (request.method !== "GET" && request.method !== "HEAD") {
    const parsed = await request.json().catch(() => ({})) as Record<string, unknown>;
    if (path === "refresh" || path === "logout") parsed.refreshToken = refreshToken ?? "";
    body = JSON.stringify(parsed);
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.requestTimeoutMs);
  try {
    return await fetch(`${config.backendUrl}${backendPath(path)}`, { method: request.method, headers, body, signal: controller.signal, cache: "no-store", redirect: "manual" });
  } finally { clearTimeout(timeout); }
}

async function handle(request: NextRequest, context: RouteContext, options: AuthNextOptions): Promise<NextResponse> {
  const config = resolveConfig(options);
  const params = await context.params;
  const path = (params.path ?? []).filter(Boolean).join("/");
  const sessionRevoke = /^sessions\/[0-9a-f-]{36}$/i.test(path) && request.method === "DELETE";
  if (
    (!ALLOWED_PATHS.has(path) && !sessionRevoke) ||
    (path === "sessions" && request.method !== "GET") ||
    (path === "application" && request.method !== "GET")
  ) {
    return publicError(404, "UNKNOWN_ERROR");
  }
  if (path === "csrf") {
    const response = json(200, { csrfToken: "issued" });
    response.cookies.set(CSRF_COOKIE, csrfValue(), { httpOnly: false, secure: isSecureRequest(request.url), sameSite: "lax", path: "/", maxAge: 7200 });
    return response;
  }
  if ((MUTATING.has(path) || sessionRevoke) && !csrfValid(request, config)) return publicError(403, "ACCESS_DENIED");
  if ((path === "me" || path === "mfa/status" || path.startsWith("sessions")) && !request.cookies.get(cookieNames(isSecureRequest(request.url)).access)?.value) {
    return publicError(401, "UNAUTHENTICATED");
  }
  if (path === "logout" && !request.cookies.get(cookieNames(isSecureRequest(request.url)).refresh)?.value) {
    const response = noContent();
    clearAuthCookies(response, request);
    return response;
  }
  let response: Response;
  try { response = await upstream(request, config, path); }
  catch {
    const result = publicError(502, "UNKNOWN_ERROR");
    if (path === "logout") clearAuthCookies(result, request);
    return result;
  }
  if (!response.ok) {
    const payload = await response.json().catch(() => ({})) as Record<string, unknown>;
    const nested = payload.error && typeof payload.error === "object" ? payload.error as Record<string, unknown> : payload;
    const upstreamCode = codeFromUpstream(nested.code);
    const code = upstreamCode === "UNKNOWN_ERROR" && response.status === 401
      ? "UNAUTHENTICATED"
      : upstreamCode;
    const result = publicError(response.status, code, typeof nested.requestId === "string" ? nested.requestId : undefined);
    if (path === "logout" || (path === "refresh" && TERMINAL_REFRESH_ERRORS.has(code))) {
      clearAuthCookies(result, request);
    }
    return result;
  }
  if (response.status === 204) {
    const result = noContent();
    if (path === "logout") clearAuthCookies(result, request);
    return result;
  }
  const payload = await response.json().catch(() => ({})) as Record<string, unknown>;
  if (!TOKEN_RESPONSES.has(path)) return json(response.status, publicSuccess(path, payload));
  const result: Record<string, unknown> = publicLogin(payload);
  if (result.otpRequired === true) {
    const output = json(response.status, result);
    clearAuthCookies(output, request);
    return output;
  }
  const accessToken = typeof payload.accessToken === "string" ? payload.accessToken : undefined;
  const refreshToken = typeof payload.refreshToken === "string" ? payload.refreshToken : undefined;
  if (!accessToken || !refreshToken) return publicError(502, "UNKNOWN_ERROR");
  delete result.accessToken;
  delete result.refreshToken;
  const output = json(response.status, result);
  setAuthCookies(
    output,
    request,
    accessToken,
    refreshToken,
    typeof payload.refreshExpiresIn === "number" ? payload.refreshExpiresIn : undefined
  );
  return output;
}

export function createAuthHandlers(options: AuthNextOptions = {}): Record<"GET" | "POST" | "PUT" | "PATCH" | "DELETE", Handler> {
  const handler = (request: NextRequest, context: RouteContext) => handle(request, context, options);
  return { GET: handler, POST: handler, PUT: handler, PATCH: handler, DELETE: handler };
}
