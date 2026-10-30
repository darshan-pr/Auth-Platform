export interface AuthNextOptions {
  backendUrl?: string;
  publishableKey?: string;
  /** Reserved for a future backend secret-authenticated contract; never sent to the browser. */
  secretKey?: string;
  allowedOrigin?: string;
  requestTimeoutMs?: number;
}

export interface AuthConfig {
  backendUrl: string;
  publishableKey: string;
  allowedOrigin?: string;
  requestTimeoutMs: number;
}

export function resolveConfig(options: AuthNextOptions = {}): AuthConfig {
  const backendUrl = (options.backendUrl ?? process.env.AUTH_PLATFORM_BACKEND_URL ?? "").trim().replace(/\/+$/, "");
  const publishableKey = (options.publishableKey ?? process.env.AUTH_PLATFORM_PUBLISHABLE_KEY ?? "").trim();
  if (!backendUrl) throw new Error("AUTH_PLATFORM_BACKEND_URL is required on the Next.js server.");
  if (!publishableKey) throw new Error("AUTH_PLATFORM_PUBLISHABLE_KEY is required on the Next.js server.");
  return {
    backendUrl,
    publishableKey,
    allowedOrigin: (options.allowedOrigin ?? process.env.AUTH_PLATFORM_ALLOWED_ORIGIN ?? "").trim() || undefined,
    requestTimeoutMs: options.requestTimeoutMs ?? 10_000
  };
}

export const ACCESS_COOKIE = "authplatform_sdk_access";
export const REFRESH_COOKIE = "authplatform_sdk_refresh";
export const CSRF_COOKIE = "authplatform_csrf";

export function cookieNames(secure: boolean) {
  return {
    access: secure ? `__Host-${ACCESS_COOKIE}` : ACCESS_COOKIE,
    refresh: secure ? `__Host-${REFRESH_COOKIE}` : REFRESH_COOKIE
  };
}

export function isSecureRequest(requestUrl?: string): boolean {
  return process.env.NODE_ENV === "production" || requestUrl?.startsWith("https:") === true;
}
