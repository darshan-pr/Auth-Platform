export type AuthErrorCode =
  | "VALIDATION_FAILED"
  | "INVALID_CREDENTIALS"
  | "EMAIL_TAKEN"
  | "RATE_LIMITED"
  | "RATE_LIMIT_UNAVAILABLE"
  | "ACCOUNT_LOCKED"
  | "MFA_REQUIRED"
  | "MFA_INVALID"
  | "OTP_EXPIRED"
  | "TOKEN_INVALID"
  | "EMAIL_NOT_VERIFIED"
  | "USER_BLOCKED"
  | "UNAUTHENTICATED"
  | "REFRESH_IN_PROGRESS"
  | "ACCESS_DENIED"
  | "UNKNOWN_ERROR";

export interface AuthUser {
  id: string;
  name: string;
  email: string;
  emailVerified: boolean;
  roles: string[];
  permissions: string[];
}

export interface SignupResponse {
  id: string | null;
  email: string;
  emailVerified: boolean;
  message: string;
}

export interface LoginResult {
  authenticated: boolean;
  user: AuthUser | null;
  otpRequired: boolean;
  challengeId?: string;
  expiresIn: number;
  refreshExpiresIn?: number;
  message?: string;
}

export interface MessageResponse {
  message: string;
}

export interface OtpChallenge extends MessageResponse {
  challengeId: string;
  expiresIn: number;
}

export interface VerifyResponse {
  emailVerified: boolean;
}

export interface MfaStatus {
  required: boolean;
  enabled: boolean;
  setupRequired: boolean;
}

export interface ApplicationBranding {
  name: string;
  iconUrl: string | null;
  iconDataUrl: string | null;
  iconPositionX: number;
  iconPositionY: number;
  iconZoomPercent: number;
}

export interface AuthSession {
  id: string;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
  lastActiveAt: string;
  expiresAt: string;
  current: boolean;
}

export interface SignUpInput {
  name: string;
  email: string;
  password: string;
}

export interface SignInInput {
  email: string;
  password: string;
  mfaCode?: string;
}

export interface AuthClientOptions {
  /** Relative BFF path. It must not be a Spring backend URL. */
  basePath?: string;
  fetch?: typeof globalThis.fetch;
  /** Reads only the non-sensitive CSRF cookie, never an auth token. */
  csrfToken?: () => string | undefined;
}

export interface SessionSnapshot {
  status: "loading" | "authenticated" | "unauthenticated" | "challenge" | "error";
  user: AuthUser | null;
  challengeId?: string;
  message?: string;
  error?: string;
}

const PUBLIC_MESSAGES: Record<AuthErrorCode, string> = {
  VALIDATION_FAILED: "Please check the highlighted fields.",
  INVALID_CREDENTIALS: "Email or password is incorrect.",
  EMAIL_TAKEN: "Unable to create an account with those details.",
  RATE_LIMITED: "Too many attempts. Please try again later.",
  RATE_LIMIT_UNAVAILABLE: "Authentication is temporarily unavailable.",
  ACCOUNT_LOCKED: "Sign-in is temporarily unavailable. Please try again later.",
  MFA_REQUIRED: "A verification code is required.",
  MFA_INVALID: "The verification code is invalid.",
  OTP_EXPIRED: "The verification code has expired.",
  TOKEN_INVALID: "That link or session is no longer valid.",
  EMAIL_NOT_VERIFIED: "Please verify your email before signing in.",
  USER_BLOCKED: "This account cannot sign in.",
  UNAUTHENTICATED: "Your session has expired. Please sign in again.",
  REFRESH_IN_PROGRESS: "Your session is still refreshing. Please retry in a moment.",
  ACCESS_DENIED: "You do not have access to this resource.",
  UNKNOWN_ERROR: "Authentication request failed."
};

export class AuthError extends Error {
  readonly code: AuthErrorCode;
  readonly status: number;
  readonly requestId?: string;
  readonly fields: Readonly<Record<string, string>>;

  constructor(
    code: AuthErrorCode,
    status: number,
    options: { requestId?: string; fields?: Record<string, string> } = {}
  ) {
    super(PUBLIC_MESSAGES[code]);
    this.name = "AuthError";
    this.code = code;
    this.status = status;
    this.requestId = options.requestId;
    this.fields = Object.freeze({ ...(options.fields ?? {}) });
  }
}

export function isAuthError(error: unknown): error is AuthError {
  return error instanceof AuthError;
}

export function validateEmail(email: string): string | undefined {
  const value = email.trim().toLowerCase();
  if (!value || value.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
    return "Enter a valid email address.";
  }
  return undefined;
}

export function validatePassword(password: string): string | undefined {
  if (password.length < 10 || password.length > 128 || !/[A-Za-z]/.test(password) || !/\d/.test(password)) {
    return "Password must be 10-128 characters and contain a letter and a number.";
  }
  return undefined;
}

export function validateSignup(input: SignUpInput): Record<string, string> {
  const errors: Record<string, string> = {};
  if (!input.name.trim() || input.name.trim().length > 120) errors.name = "Enter your name.";
  const emailError = validateEmail(input.email);
  if (emailError) errors.email = emailError;
  const passwordError = validatePassword(input.password);
  if (passwordError) errors.password = passwordError;
  const emailLocalPart = input.email.trim().split("@")[0]?.toLowerCase();
  if (!passwordError && emailLocalPart && input.password.toLowerCase().includes(emailLocalPart)) {
    errors.password = "Password must not contain the part of your email before @.";
  }
  return errors;
}

function normalizeCode(value: unknown): AuthErrorCode {
  const allowed: AuthErrorCode[] = [
    "VALIDATION_FAILED", "INVALID_CREDENTIALS", "EMAIL_TAKEN", "RATE_LIMITED",
    "RATE_LIMIT_UNAVAILABLE", "ACCOUNT_LOCKED", "MFA_REQUIRED", "MFA_INVALID",
    "OTP_EXPIRED", "TOKEN_INVALID", "EMAIL_NOT_VERIFIED", "USER_BLOCKED",
    "UNAUTHENTICATED", "REFRESH_IN_PROGRESS", "ACCESS_DENIED"
  ];
  return typeof value === "string" && allowed.includes(value as AuthErrorCode)
    ? (value as AuthErrorCode)
    : "UNKNOWN_ERROR";
}

export async function authErrorFromResponse(response: Response): Promise<AuthError> {
  let payload: unknown;
  try { payload = await response.json(); } catch { payload = undefined; }
  const body = payload && typeof payload === "object" ? payload as Record<string, unknown> : {};
  const nested = body.error && typeof body.error === "object" ? body.error as Record<string, unknown> : body;
  const fields: Record<string, string> = {};
  if (Array.isArray(nested.fields)) {
    for (const field of nested.fields) {
      if (field && typeof field === "object") {
        const item = field as Record<string, unknown>;
        if (typeof item.field === "string") fields[item.field] = "Invalid value.";
      }
    }
  }
  return new AuthError(normalizeCode(nested.code), response.status, {
    requestId: typeof nested.requestId === "string" ? nested.requestId : undefined,
    fields
  });
}

function userFromPayload(value: unknown): AuthUser | null {
  if (!value || typeof value !== "object") return null;
  const data = value as Record<string, unknown>;
  if (typeof data.id !== "string" || typeof data.email !== "string") return null;
  return {
    id: data.id,
    name: typeof data.name === "string" ? data.name : "",
    email: data.email,
    emailVerified: data.emailVerified === true,
    roles: Array.isArray(data.roles) ? data.roles.filter((role): role is string => typeof role === "string") : [],
    permissions: Array.isArray(data.permissions) ? data.permissions.filter((permission): permission is string => typeof permission === "string") : []
  };
}

function loginFromPayload(value: unknown): LoginResult {
  const data = value && typeof value === "object" ? value as Record<string, unknown> : {};
  return {
    authenticated: data.authenticated === true && data.otpRequired !== true,
    user: data.otpRequired === true ? null : userFromPayload(data.user),
    otpRequired: data.otpRequired === true,
    challengeId: typeof data.challengeId === "string" ? data.challengeId : undefined,
    expiresIn: typeof data.expiresIn === "number" ? data.expiresIn : 0,
    refreshExpiresIn: typeof data.refreshExpiresIn === "number" ? data.refreshExpiresIn : undefined,
    message: typeof data.message === "string" ? data.message : undefined
  };
}

export class AuthSessionState {
  private snapshot: SessionSnapshot = { status: "loading", user: null };
  private readonly listeners = new Set<(snapshot: SessionSnapshot) => void>();

  get value(): SessionSnapshot { return this.snapshot; }

  subscribe(listener: (snapshot: SessionSnapshot) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  set(snapshot: SessionSnapshot): void {
    this.snapshot = snapshot;
    for (const listener of this.listeners) listener(snapshot);
  }
}

function withBrowserRefreshLock<T>(name: string, operation: () => Promise<T>): Promise<T> {
  if (typeof navigator === "undefined" || !navigator.locks) return operation();
  return Promise.resolve(navigator.locks.request(name, operation));
}

export class AuthClient {
  private readonly basePath: string;
  private readonly requestFetch: typeof globalThis.fetch;
  private readonly csrfToken?: () => string | undefined;
  private refreshInFlight?: Promise<LoginResult>;

  constructor(options: AuthClientOptions = {}) {
    this.basePath = (options.basePath ?? "/api/auth").replace(/\/+$/, "") || "/api/auth";
    this.requestFetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.csrfToken = options.csrfToken ?? (() => {
      if (typeof document === "undefined") return undefined;
      return document.cookie.split("; ").find((item) => item.startsWith("authplatform_csrf="))?.split("=").slice(1).join("=");
    });
  }

  async signUp(input: SignUpInput): Promise<SignupResponse> {
    const errors = validateSignup(input);
    if (Object.keys(errors).length) throw new AuthError("VALIDATION_FAILED", 400, { fields: errors });
    return this.request<SignupResponse>("/signup", { method: "POST", body: input });
  }

  async signIn(input: SignInInput): Promise<LoginResult> {
    const emailError = validateEmail(input.email);
    if (emailError) throw new AuthError("VALIDATION_FAILED", 400, { fields: { email: emailError } });
    if (!input.password) throw new AuthError("VALIDATION_FAILED", 400, { fields: { password: "Password is required." } });
    return loginFromPayload(await this.request<unknown>("/login", { method: "POST", body: input }));
  }

  async verifyOtp(challengeId: string, code: string): Promise<LoginResult> {
    if (!challengeId || !/^\d{6}$/.test(code)) throw new AuthError("MFA_INVALID", 400);
    return loginFromPayload(await this.request<unknown>("/login/otp", { method: "POST", body: { challengeId, code } }));
  }

  async resendLoginOtp(challengeId: string): Promise<OtpChallenge> {
    if (!challengeId) throw new AuthError("MFA_INVALID", 400);
    return this.request<OtpChallenge>("/login/otp/resend", {
      method: "POST",
      body: { challengeId }
    });
  }

  async refresh(): Promise<LoginResult> {
    if (this.refreshInFlight) return this.refreshInFlight;
    const refresh = withBrowserRefreshLock(
      `authplatform:refresh:${this.basePath}`,
      async () => {
        for (let attempt = 0; attempt < 3; attempt += 1) {
          try {
            return loginFromPayload(await this.request<unknown>("/refresh", { method: "POST", body: {} }));
          } catch (error) {
            if (!(error instanceof AuthError) || error.code !== "REFRESH_IN_PROGRESS" || attempt === 2) {
              throw error;
            }
            await new Promise((resolve) => setTimeout(resolve, 100 * (attempt + 1)));
          }
        }
        throw new AuthError("REFRESH_IN_PROGRESS", 409);
      }
    );
    this.refreshInFlight = refresh;
    try {
      return await refresh;
    } finally {
      if (this.refreshInFlight === refresh) this.refreshInFlight = undefined;
    }
  }

  async signOut(): Promise<void> {
    await this.request<unknown>("/logout", { method: "POST", body: {} });
  }

  async verifyEmail(token: string): Promise<VerifyResponse> {
    return this.request<VerifyResponse>("/verify-email", { method: "POST", body: { token } });
  }

  async resendVerification(email: string): Promise<MessageResponse> {
    return this.request<MessageResponse>("/resend-verification", { method: "POST", body: { email } });
  }

  async forgotPassword(email: string): Promise<MessageResponse> {
    return this.request<MessageResponse>("/forgot-password", { method: "POST", body: { email } });
  }

  async startPasswordReset(email: string): Promise<OtpChallenge> {
    const emailError = validateEmail(email);
    if (emailError) throw new AuthError("VALIDATION_FAILED", 400, { fields: { email: emailError } });
    return this.request<OtpChallenge>("/forgot-password/otp", {
      method: "POST",
      body: { email }
    });
  }

  async resendPasswordResetOtp(challengeId: string): Promise<OtpChallenge> {
    if (!challengeId) throw new AuthError("OTP_EXPIRED", 400);
    return this.request<OtpChallenge>("/forgot-password/otp/resend", {
      method: "POST",
      body: { challengeId }
    });
  }

  async resetPasswordWithOtp(
    challengeId: string,
    code: string,
    newPassword: string
  ): Promise<MessageResponse> {
    if (!challengeId || !/^\d{6}$/.test(code)) {
      throw new AuthError("MFA_INVALID", 400, { fields: { code: "Enter the 6-digit code." } });
    }
    const passwordError = validatePassword(newPassword);
    if (passwordError) {
      throw new AuthError("VALIDATION_FAILED", 400, { fields: { newPassword: passwordError } });
    }
    return this.request<MessageResponse>("/reset-password/otp", {
      method: "POST",
      body: { challengeId, code, newPassword }
    });
  }

  async resetPassword(token: string, newPassword: string): Promise<MessageResponse> {
    const passwordError = validatePassword(newPassword);
    if (passwordError) throw new AuthError("VALIDATION_FAILED", 400, { fields: { newPassword: passwordError } });
    return this.request<MessageResponse>("/reset-password", { method: "POST", body: { token, newPassword } });
  }

  async getUser(): Promise<AuthUser | null> {
    try { return userFromPayload(await this.request<unknown>("/me")); }
    catch (error) {
      if (error instanceof AuthError && ["UNAUTHENTICATED", "TOKEN_INVALID"].includes(error.code)) return null;
      throw error;
    }
  }

  async getApplicationBranding(): Promise<ApplicationBranding> {
    const value = await this.request<unknown>("/application");
    if (!value || typeof value !== "object") throw new AuthError("UNKNOWN_ERROR", 502);
    const data = value as Record<string, unknown>;
    if (
      typeof data.name !== "string" ||
      typeof data.iconPositionX !== "number" ||
      typeof data.iconPositionY !== "number" ||
      typeof data.iconZoomPercent !== "number"
    ) {
      throw new AuthError("UNKNOWN_ERROR", 502);
    }
    return {
      name: data.name,
      iconUrl: typeof data.iconUrl === "string" ? data.iconUrl : null,
      iconDataUrl: typeof data.iconDataUrl === "string" ? data.iconDataUrl : null,
      iconPositionX: data.iconPositionX,
      iconPositionY: data.iconPositionY,
      iconZoomPercent: data.iconZoomPercent
    };
  }

  async getSessions(): Promise<AuthSession[]> {
    return this.request<AuthSession[]>("/sessions");
  }

  async revokeSession(sessionId: string): Promise<void> {
    if (!sessionId) throw new AuthError("VALIDATION_FAILED", 400);
    await this.request<void>(`/sessions/${encodeURIComponent(sessionId)}`, { method: "DELETE" });
  }

  async mfaStatus(): Promise<MfaStatus> {
    return this.request<MfaStatus>("/mfa/status");
  }

  private async request<T>(
    path: string,
    init: { method?: string; body?: unknown } = {},
    allowRefresh = true
  ): Promise<T> {
    const method = init.method ?? "GET";
    const headers = new Headers({ Accept: "application/json" });
    if (init.body !== undefined) headers.set("Content-Type", "application/json");
    if (method !== "GET" && method !== "HEAD") {
      let csrf = this.csrfToken?.();
      if (!csrf && typeof document !== "undefined") {
        await this.requestFetch(`${this.basePath}/csrf`, { method: "GET", credentials: "include", cache: "no-store" });
        csrf = this.csrfToken?.();
      }
      if (csrf) headers.set("X-Authplatform-CSRF", csrf);
    }
    const response = await this.requestFetch(`${this.basePath}${path}`, {
      method,
      headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      credentials: "include",
      cache: "no-store"
    });
    if (!response.ok) {
      const error = await authErrorFromResponse(response);
      if (
        allowRefresh &&
        error.code === "UNAUTHENTICATED" &&
        (path === "/me" || path === "/mfa/status" || path === "/sessions" || path.startsWith("/sessions/"))
      ) {
        await this.refresh();
        return this.request<T>(path, init, false);
      }
      throw error;
    }
    if (response.status === 204) return undefined as T;
    return await response.json() as T;
  }
}
