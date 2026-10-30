import "server-only";

import { cookies } from "next/headers";
import { AuthError, type AuthUser } from "@authplatform/auth-core";
import { AuthNextOptions, cookieNames, resolveConfig } from "./config.js";

export interface AuthResult { isAuthenticated: boolean; user: AuthUser | null; }

async function serverUser(options: AuthNextOptions): Promise<AuthUser | null> {
  const config = resolveConfig(options);
  const store = await cookies();
  const token = store.get(cookieNames(process.env.NODE_ENV === "production").access)?.value;
  if (!token) return null;
  const response = await fetch(`${config.backendUrl}/api/v1/users/me`, {
    headers: { Accept: "application/json", Authorization: `Bearer ${token}`, "X-authplatform-Key": config.publishableKey },
    cache: "no-store"
  });
  if (response.status === 401 || response.status === 403) return null;
  if (!response.ok) throw new AuthError("UNKNOWN_ERROR", response.status);
  const payload = await response.json() as Record<string, unknown>;
  if (typeof payload.id !== "string" || typeof payload.email !== "string") return null;
  return {
    id: payload.id, name: typeof payload.name === "string" ? payload.name : "", email: payload.email,
    emailVerified: payload.emailVerified === true,
    roles: Array.isArray(payload.roles) ? payload.roles.filter((role): role is string => typeof role === "string") : [],
    permissions: Array.isArray(payload.permissions) ? payload.permissions.filter((permission): permission is string => typeof permission === "string") : []
  };
}

export async function auth(options: AuthNextOptions = {}): Promise<AuthResult> {
  const user = await serverUser(options);
  return { isAuthenticated: Boolean(user), user };
}

export async function currentUser(options: AuthNextOptions = {}): Promise<AuthUser | null> {
  return serverUser(options);
}

export class AuthRequiredError extends Error {
  constructor() { super("Authentication is required."); this.name = "AuthRequiredError"; }
}

export async function requireAuth(options: AuthNextOptions = {}): Promise<AuthUser> {
  const user = await serverUser(options);
  if (!user) throw new AuthRequiredError();
  return user;
}
