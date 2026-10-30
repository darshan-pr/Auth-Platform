import type { Account, AccountDetails, Analytics, App, AppUser, AppUserDetails, AuditLog, ConsoleAccount, ConsoleApp, PageResponse, RotatedSecret, MfaStatus, Role, Permission, LoginResponse, OtpChallenge } from "./types";

export const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";
type AuthScope = "sa" | "console";

export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;

  constructor(
    message: string,
    status: number,
    code?: string,
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

async function apiErrorFromResponse(response: Response): Promise<ApiError> {
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    payload = undefined;
  }
  const body = payload && typeof payload === "object" ? payload as Record<string, unknown> : {};
  const rawError = body.error;
  const error = rawError && typeof rawError === "object"
    ? rawError as Record<string, unknown>
    : body;
  const message =
    typeof error.message === "string"
      ? error.message
      : typeof rawError === "string"
        ? rawError
        : typeof body.message === "string"
          ? body.message
          : `Request failed (${response.status})`;
  return new ApiError(message, response.status, typeof error.code === "string" ? error.code : undefined);
}

async function csrfToken(scope: AuthScope, refresh = false): Promise<string> {
  const cookie = document.cookie.split("; ").find((value) => value.startsWith("XSRF-TOKEN="))?.split("=").slice(1).join("=");
  if (cookie && !refresh) return decodeURIComponent(cookie);

  const response = await fetch(`${API_BASE}/api/${scope}/csrf`, {
    headers: { "X-Requested-With": scope === "console" ? "authplatform-console" : "authplatform-sa" },
    credentials: "include",
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`Unable to initialize secure request (${response.status})`);
  const payload = await response.json() as { token?: unknown };
  if (typeof payload.token !== "string" || !payload.token) {
    throw new Error("The server did not return a CSRF token.");
  }
  return payload.token;
}

const refreshesInFlight = new Map<AuthScope, Promise<boolean>>();

function withBrowserRefreshLock<T>(scope: AuthScope, operation: () => Promise<T>): Promise<T> {
  if (typeof navigator === "undefined" || !navigator.locks) return operation();
  return Promise.resolve(navigator.locks.request(`authplatform:${API_BASE}:${scope}:refresh`, operation));
}

function refreshSession(scope: AuthScope): Promise<boolean> {
  const inFlight = refreshesInFlight.get(scope);
  if (inFlight) return inFlight;

  const path = scope === "console" ? "/api/console/auth/refresh" : "/api/sa/auth/refresh";
  const requested = scope === "console" ? "authplatform-console" : "authplatform-sa";
  const refresh = withBrowserRefreshLock(scope, async () => {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const response = await fetch(`${API_BASE}${path}`, {
        method: "POST",
        headers: { "X-Requested-With": requested },
        credentials: "include",
        cache: "no-store",
      });
      if (response.ok) return true;
      const error = await apiErrorFromResponse(response);
      if (error.code === "REFRESH_IN_PROGRESS" && attempt < 2) {
        await new Promise((resolve) => setTimeout(resolve, 100 * (attempt + 1)));
        continue;
      }
      if (
        response.status === 401 ||
        ["TOKEN_INVALID", "UNAUTHENTICATED", "USER_BLOCKED", "ACCOUNT_LOCKED"].includes(error.code ?? "")
      ) {
        return false;
      }
      throw error;
    }
    return false;
  })
    .finally(() => {
      refreshesInFlight.delete(scope);
    });
  refreshesInFlight.set(scope, refresh);
  return refresh;
}

export async function apiFetch<T>(
  path: string,
  init: RequestInit = {},
  scope: AuthScope = "sa",
  retried = false,
  csrfRetried = false,
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  headers.set("X-Requested-With", scope === "console" ? "authplatform-console" : "authplatform-sa");
  const method = (init.method ?? "GET").toUpperCase();
  const requiresCsrf =
    ["POST", "PUT", "PATCH", "DELETE"].includes(method) &&
    !path.startsWith(`/api/${scope}/auth/`);
  if (requiresCsrf) {
    headers.set("X-XSRF-TOKEN", await csrfToken(scope, csrfRetried));
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
    credentials: "include",
    cache: "no-store",
  });

  if (response.status === 401 && !retried && !path.includes("/auth/login") && !path.includes("/auth/refresh") && !path.includes("/auth/logout")) {
    if (await refreshSession(scope)) return apiFetch<T>(path, init, scope, true, csrfRetried);
  }

  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  if (response.status === 403 && requiresCsrf && !csrfRetried && !contentType.includes("json")) {
    return apiFetch<T>(path, init, scope, retried, true);
  }

  if (!response.ok) throw await apiErrorFromResponse(response);

  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export const api = {
  health: () => apiFetch<{ status: string; components?: Record<string, { status: string }> }>("/actuator/health"),
  login: (email: string, password: string) =>
    apiFetch<LoginResponse<Account>>("/api/sa/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  verifyOtp: (challengeId: string, code: string) =>
    apiFetch<{ account: Account }>("/api/sa/auth/login/otp", {
      method: "POST",
      body: JSON.stringify({ challengeId, code }),
    }),
  resendLoginOtp: (challengeId: string) =>
    apiFetch<OtpChallenge>("/api/sa/auth/login/otp/resend", {
      method: "POST",
      body: JSON.stringify({ challengeId }),
    }),
  forgotPassword: (email: string) =>
    apiFetch<OtpChallenge>("/api/sa/auth/forgot-password", {
      method: "POST",
      body: JSON.stringify({ email }),
    }),
  resendPasswordResetOtp: (challengeId: string) =>
    apiFetch<OtpChallenge>("/api/sa/auth/forgot-password/otp/resend", {
      method: "POST",
      body: JSON.stringify({ challengeId }),
    }),
  resetPassword: (challengeId: string, code: string, newPassword: string) =>
    apiFetch<{ message: string }>("/api/sa/auth/reset-password", {
      method: "POST",
      body: JSON.stringify({ challengeId, code, newPassword }),
    }),
  logout: () =>
    apiFetch<void>("/api/sa/auth/logout", {
      method: "POST",
      headers: { "X-Requested-With": "authplatform-sa" },
    }),
  sessions: () => apiFetch<import("./types").SessionInfo[]>("/api/sa/sessions"),
  revokeSession: (id: string) => apiFetch<void>(`/api/sa/sessions/${id}`, { method: "DELETE" }),
  analytics: () => apiFetch<Analytics>("/api/sa/analytics/overview"),
  me: () => apiFetch<Account>("/api/sa/me"),
  accounts: (page = 0, size = 20) => apiFetch<PageResponse<Account>>(`/api/sa/accounts?page=${page}&size=${size}`),
  account: (id: string) => apiFetch<AccountDetails>(`/api/sa/accounts/${id}`),
  createSa: (payload: { name: string; email: string; password: string }) =>
    apiFetch<Account>("/api/sa/accounts", { method: "POST", body: JSON.stringify(payload) }),
  updateAccount: (id: string, payload: Record<string, unknown>) =>
    apiFetch<Account>(`/api/sa/accounts/${id}`, { method: "PATCH", body: JSON.stringify(payload) }),
  apps: (page = 0) => apiFetch<PageResponse<App>>(`/api/sa/apps?page=${page}&size=20`),
  app: (id: string) => apiFetch<App>(`/api/sa/apps/${id}`),
  updateApp: (id: string, payload: Record<string, unknown>) =>
    apiFetch<App>(`/api/sa/apps/${id}`, { method: "PATCH", body: JSON.stringify(payload) }),
  rotateSecret: (id: string) =>
    apiFetch<{ appId: string; secretKey: string; secretKeyHint: string }>(
      `/api/sa/apps/${id}/credentials/rotate`,
      { method: "POST" },
    ),
  users: (page = 0) => apiFetch<PageResponse<AppUser>>(`/api/sa/users?page=${page}&size=20`),
  appUsers: (appId: string, page = 0) =>
    apiFetch<PageResponse<AppUser>>(`/api/sa/apps/${appId}/users?page=${page}&size=20`),
  updateUser: (appId: string, userId: string, payload: Record<string, unknown>) =>
    apiFetch<AppUser>(`/api/sa/apps/${appId}/users/${userId}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  deleteUser: (appId: string, userId: string) =>
    apiFetch<void>(`/api/sa/apps/${appId}/users/${userId}`, { method: "DELETE" }),
  appUserSessions: (appId: string, userId: string) =>
    apiFetch<import("./types").SessionInfo[]>(`/api/sa/apps/${appId}/users/${userId}/sessions`),
  revokeAppUserSession: (appId: string, userId: string, sessionId: string) =>
    apiFetch<void>(`/api/sa/apps/${appId}/users/${userId}/sessions/${sessionId}`, { method: "DELETE" }),
  revokeAllAppUserSessions: (appId: string, userId: string) =>
    apiFetch<void>(`/api/sa/apps/${appId}/users/${userId}/sessions`, { method: "DELETE" }),
  auditLogs: (page = 0) =>
    apiFetch<PageResponse<AuditLog>>(`/api/sa/audit-logs?page=${page}&size=50`),
  mfaStatus: () => apiFetch<MfaStatus>("/api/sa/mfa/status"),
  roles: (appId: string) => apiFetch<Role[]>(`/api/sa/apps/${appId}/roles`),
  permissions: (appId: string) => apiFetch<Permission[]>(`/api/sa/apps/${appId}/permissions`),
  rolePermissions: (appId: string, roleId: string) => apiFetch<Permission[]>(`/api/sa/apps/${appId}/roles/${roleId}/permissions`),
  rolePermissionUsers: (appId: string, roleId: string, permissionId: string) => apiFetch<import("./types").RolePermissionUser[]>(`/api/sa/apps/${appId}/roles/${roleId}/permissions/${permissionId}/users`),
  createRole: (appId: string, payload: { name: string; displayName?: string; description?: string; defaultRole?: boolean; permissions?: { key: string; description?: string }[] }) => apiFetch<Role>(`/api/sa/apps/${appId}/roles`, { method: "POST", body: JSON.stringify(payload) }),
  updateRole: (appId: string, roleId: string, payload: { name?: string; displayName?: string; description?: string; enabled?: boolean; defaultRole?: boolean }) => apiFetch<Role>(`/api/sa/apps/${appId}/roles/${roleId}`, { method: "PATCH", body: JSON.stringify(payload) }),
  createPermission: (appId: string, roleId: string, payload: { key: string; description?: string }) => apiFetch<Permission>(`/api/sa/apps/${appId}/permissions`, { method: "POST", body: JSON.stringify({ ...payload, roleId }) }),
  updatePermission: (appId: string, permissionId: string, payload: { key?: string; description?: string }) => apiFetch<Permission>(`/api/sa/apps/${appId}/permissions/${permissionId}`, { method: "PATCH", body: JSON.stringify(payload) }),
  deletePermission: (appId: string, permissionId: string) => apiFetch<void>(`/api/sa/apps/${appId}/permissions/${permissionId}`, { method: "DELETE" }),
  assignRole: (appId: string, userId: string, roleId: string) => apiFetch<void>(`/api/sa/apps/${appId}/users/${userId}/roles/${roleId}`, { method: "POST" }),
  removeRole: (appId: string, userId: string, roleId: string) => apiFetch<void>(`/api/sa/apps/${appId}/users/${userId}/roles/${roleId}`, { method: "DELETE" }),
  assignPermission: (appId: string, roleId: string, permissionId: string) => apiFetch<void>(`/api/sa/apps/${appId}/roles/${roleId}/permissions`, { method: "POST", body: JSON.stringify({ permissionId }) }),
  removePermission: (appId: string, roleId: string, permissionId: string) => apiFetch<void>(`/api/sa/apps/${appId}/roles/${roleId}/permissions/${permissionId}`, { method: "DELETE" }),
  assignPermissions: (appId: string, roleId: string, payload: { permissionIds: string[]; newPermissions: { key: string; description?: string }[] }) => apiFetch<void>(`/api/sa/apps/${appId}/roles/${roleId}/permissions/batch`, { method: "POST", body: JSON.stringify(payload) }),
  setRolePermissions: (appId: string, roleId: string, payload: { permissionIds: string[]; enabled: boolean }) => apiFetch<void>(`/api/sa/apps/${appId}/roles/${roleId}/permissions`, { method: "PUT", body: JSON.stringify(payload) }),
  setRolePermissionStates: (appId: string, roleId: string, payload: { enablePermissionIds: string[]; disablePermissionIds: string[] }) => apiFetch<void>(`/api/sa/apps/${appId}/roles/${roleId}/permissions`, { method: "PATCH", body: JSON.stringify(payload) }),
  setUserRolePermissions: (appId: string, userId: string, roleId: string, payload: { permissionIds: string[]; granted: boolean }) => apiFetch<void>(`/api/sa/apps/${appId}/users/${userId}/roles/${roleId}/permissions`, { method: "PUT", body: JSON.stringify(payload) }),
  setUserRolePermissionStates: (appId: string, userId: string, roleId: string, payload: { enablePermissionIds: string[]; disablePermissionIds: string[] }) => apiFetch<void>(`/api/sa/apps/${appId}/users/${userId}/roles/${roleId}/permissions`, { method: "PATCH", body: JSON.stringify(payload) }),
  setUserRolePermission: (appId: string, userId: string, roleId: string, permissionId: string, granted: boolean) => apiFetch<void>(`/api/sa/apps/${appId}/users/${userId}/roles/${roleId}/permissions/${permissionId}`, { method: "PUT", body: JSON.stringify({ granted }) }),
};

export const consoleApi = {
  login: (email: string, password: string) =>
    apiFetch<LoginResponse<ConsoleAccount>>("/api/console/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }, "console"),
  verifyOtp: (challengeId: string, code: string) =>
    apiFetch<{ account: ConsoleAccount }>("/api/console/auth/login/otp", {
      method: "POST",
      body: JSON.stringify({ challengeId, code }),
    }, "console"),
  resendLoginOtp: (challengeId: string) =>
    apiFetch<OtpChallenge>("/api/console/auth/login/otp/resend", {
      method: "POST",
      body: JSON.stringify({ challengeId }),
    }, "console"),
  forgotPassword: (email: string) =>
    apiFetch<OtpChallenge>("/api/console/auth/forgot-password", {
      method: "POST",
      body: JSON.stringify({ email }),
    }, "console"),
  resendPasswordResetOtp: (challengeId: string) =>
    apiFetch<OtpChallenge>("/api/console/auth/forgot-password/otp/resend", {
      method: "POST",
      body: JSON.stringify({ challengeId }),
    }, "console"),
  resetPassword: (challengeId: string, code: string, newPassword: string) =>
    apiFetch<{ message: string }>("/api/console/auth/reset-password", {
      method: "POST",
      body: JSON.stringify({ challengeId, code, newPassword }),
    }, "console"),
  resendVerification: (email: string) =>
    apiFetch<{ message: string }>("/api/console/auth/resend-verification", {
      method: "POST",
      body: JSON.stringify({ email }),
    }, "console"),
  signup: (payload: { name: string; email: string; password: string }) =>
    apiFetch<{ id: string; email: string; emailVerified: boolean; message: string }>("/api/console/auth/signup", {
      method: "POST",
      body: JSON.stringify(payload),
    }, "console"),
  logout: () => apiFetch<void>("/api/console/auth/logout", {
    method: "POST",
    headers: { "X-Requested-With": "authplatform-console" },
  }, "console"),
  sessions: () => apiFetch<import("./types").SessionInfo[]>("/api/console/sessions", {}, "console"),
  revokeSession: (id: string) => apiFetch<void>(`/api/console/sessions/${id}`, { method: "DELETE" }, "console"),
  me: () => apiFetch<ConsoleAccount>("/api/console/me", {}, "console"),
  apps: () => apiFetch<ConsoleApp[]>("/api/console/apps", {}, "console"),
  app: (id: string) => apiFetch<ConsoleApp>(`/api/console/apps/${id}`, {}, "console"),
  createApp: (payload: { name: string; allowedOrigins: string[]; verifyEmailUrl?: string; resetPasswordUrl?: string; mfaRequired?: boolean; accessTokenTtlSeconds?: number; refreshTokenTtlSeconds?: number }) =>
    apiFetch<ConsoleApp & { secretKey: string }>("/api/console/apps", { method: "POST", body: JSON.stringify(payload) }, "console"),
  updateApp: (id: string, payload: Record<string, unknown>) =>
    apiFetch<ConsoleApp>(`/api/console/apps/${id}`, { method: "PATCH", body: JSON.stringify(payload) }, "console"),
  rotateSecret: (id: string) =>
    apiFetch<RotatedSecret>(`/api/console/apps/${id}/credentials/rotate`, { method: "POST" }, "console"),
  appUsers: (id: string) => apiFetch<import("./types").AppUser[]>(`/api/console/apps/${id}/users`, {}, "console"),
  appUserDetails: (appId: string, userId: string) => apiFetch<AppUserDetails>(`/api/console/apps/${appId}/users/${userId}/details`, {}, "console"),
  updateUser: (appId: string, userId: string, payload: Record<string, unknown>) => apiFetch<import("./types").AppUser>(`/api/console/apps/${appId}/users/${userId}`, { method: "PATCH", body: JSON.stringify(payload) }, "console"),
  deleteUser: (appId: string, userId: string) => apiFetch<void>(`/api/console/apps/${appId}/users/${userId}`, { method: "DELETE" }, "console"),
  appUserSessions: (appId: string, userId: string) => apiFetch<import("./types").SessionInfo[]>(`/api/console/apps/${appId}/users/${userId}/sessions`, {}, "console"),
  revokeAppUserSession: (appId: string, userId: string, sessionId: string) => apiFetch<void>(`/api/console/apps/${appId}/users/${userId}/sessions/${sessionId}`, { method: "DELETE" }, "console"),
  revokeAllAppUserSessions: (appId: string, userId: string) => apiFetch<void>(`/api/console/apps/${appId}/users/${userId}/sessions`, { method: "DELETE" }, "console"),
  assignRole: (appId: string, userId: string, roleId: string) => apiFetch<void>(`/api/console/apps/${appId}/users/${userId}/roles/${roleId}`, { method: "POST" }, "console"),
  removeRole: (appId: string, userId: string, roleId: string) => apiFetch<void>(`/api/console/apps/${appId}/users/${userId}/roles/${roleId}`, { method: "DELETE" }, "console"),
  setUserRolePermission: (appId: string, userId: string, roleId: string, permissionId: string, granted: boolean) => apiFetch<void>(`/api/console/apps/${appId}/users/${userId}/roles/${roleId}/permissions/${permissionId}`, { method: "PUT", body: JSON.stringify({ granted }) }, "console"),
  mfaStatus: () => apiFetch<MfaStatus>("/api/console/mfa/status", {}, "console"),
  roles: (appId: string) => apiFetch<Role[]>(`/api/console/apps/${appId}/roles`, {}, "console"),
  permissions: (appId: string) => apiFetch<Permission[]>(`/api/console/apps/${appId}/permissions`, {}, "console"),
  rolePermissions: (appId: string, roleId: string) => apiFetch<Permission[]>(`/api/console/apps/${appId}/roles/${roleId}/permissions`, {}, "console"),
  rolePermissionUsers: (appId: string, roleId: string, permissionId: string) => apiFetch<import("./types").RolePermissionUser[]>(`/api/console/apps/${appId}/roles/${roleId}/permissions/${permissionId}/users`, {}, "console"),
  createRole: (appId: string, payload: { name: string; displayName?: string; description?: string; defaultRole?: boolean; permissions?: { key: string; description?: string }[] }) => apiFetch<Role>(`/api/console/apps/${appId}/roles`, { method: "POST", body: JSON.stringify(payload) }, "console"),
  updateRole: (appId: string, roleId: string, payload: { name?: string; displayName?: string; description?: string; enabled?: boolean; defaultRole?: boolean }) => apiFetch<Role>(`/api/console/apps/${appId}/roles/${roleId}`, { method: "PATCH", body: JSON.stringify(payload) }, "console"),
  createPermission: (appId: string, roleId: string, payload: { key: string; description?: string }) => apiFetch<Permission>(`/api/console/apps/${appId}/permissions`, { method: "POST", body: JSON.stringify({ ...payload, roleId }) }, "console"),
  updatePermission: (appId: string, permissionId: string, payload: { key?: string; description?: string }) => apiFetch<Permission>(`/api/console/apps/${appId}/permissions/${permissionId}`, { method: "PATCH", body: JSON.stringify(payload) }, "console"),
  deletePermission: (appId: string, permissionId: string) => apiFetch<void>(`/api/console/apps/${appId}/permissions/${permissionId}`, { method: "DELETE" }, "console"),
  assignPermissions: (appId: string, roleId: string, payload: { permissionIds: string[]; newPermissions: { key: string; description?: string }[] }) => apiFetch<void>(`/api/console/apps/${appId}/roles/${roleId}/permissions/batch`, { method: "POST", body: JSON.stringify(payload) }, "console"),
  setRolePermissions: (appId: string, roleId: string, payload: { permissionIds: string[]; enabled: boolean }) => apiFetch<void>(`/api/console/apps/${appId}/roles/${roleId}/permissions`, { method: "PUT", body: JSON.stringify(payload) }, "console"),
  setRolePermissionStates: (appId: string, roleId: string, payload: { enablePermissionIds: string[]; disablePermissionIds: string[] }) => apiFetch<void>(`/api/console/apps/${appId}/roles/${roleId}/permissions`, { method: "PATCH", body: JSON.stringify(payload) }, "console"),
  setUserRolePermissions: (appId: string, userId: string, roleId: string, payload: { permissionIds: string[]; granted: boolean }) => apiFetch<void>(`/api/console/apps/${appId}/users/${userId}/roles/${roleId}/permissions`, { method: "PUT", body: JSON.stringify(payload) }, "console"),
  setUserRolePermissionStates: (appId: string, userId: string, roleId: string, payload: { enablePermissionIds: string[]; disablePermissionIds: string[] }) => apiFetch<void>(`/api/console/apps/${appId}/users/${userId}/roles/${roleId}/permissions`, { method: "PATCH", body: JSON.stringify(payload) }, "console"),
  assignPermission: (appId: string, roleId: string, permissionId: string) => apiFetch<void>(`/api/console/apps/${appId}/roles/${roleId}/permissions`, { method: "POST", body: JSON.stringify({ permissionId }) }, "console"),
  removePermission: (appId: string, roleId: string, permissionId: string) => apiFetch<void>(`/api/console/apps/${appId}/roles/${roleId}/permissions/${permissionId}`, { method: "DELETE" }, "console"),
};
