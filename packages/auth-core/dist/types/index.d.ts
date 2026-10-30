export type AuthErrorCode = "VALIDATION_FAILED" | "INVALID_CREDENTIALS" | "EMAIL_TAKEN" | "RATE_LIMITED" | "RATE_LIMIT_UNAVAILABLE" | "ACCOUNT_LOCKED" | "MFA_REQUIRED" | "MFA_INVALID" | "OTP_EXPIRED" | "TOKEN_INVALID" | "EMAIL_NOT_VERIFIED" | "USER_BLOCKED" | "UNAUTHENTICATED" | "REFRESH_IN_PROGRESS" | "ACCESS_DENIED" | "UNKNOWN_ERROR";
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
export declare class AuthError extends Error {
    readonly code: AuthErrorCode;
    readonly status: number;
    readonly requestId?: string;
    readonly fields: Readonly<Record<string, string>>;
    constructor(code: AuthErrorCode, status: number, options?: {
        requestId?: string;
        fields?: Record<string, string>;
    });
}
export declare function isAuthError(error: unknown): error is AuthError;
export declare function validateEmail(email: string): string | undefined;
export declare function validatePassword(password: string): string | undefined;
export declare function validateSignup(input: SignUpInput): Record<string, string>;
export declare function authErrorFromResponse(response: Response): Promise<AuthError>;
export declare class AuthSessionState {
    private snapshot;
    private readonly listeners;
    get value(): SessionSnapshot;
    subscribe(listener: (snapshot: SessionSnapshot) => void): () => void;
    set(snapshot: SessionSnapshot): void;
}
export declare class AuthClient {
    private readonly basePath;
    private readonly requestFetch;
    private readonly csrfToken?;
    private refreshInFlight?;
    constructor(options?: AuthClientOptions);
    signUp(input: SignUpInput): Promise<SignupResponse>;
    signIn(input: SignInInput): Promise<LoginResult>;
    verifyOtp(challengeId: string, code: string): Promise<LoginResult>;
    resendLoginOtp(challengeId: string): Promise<OtpChallenge>;
    refresh(): Promise<LoginResult>;
    signOut(): Promise<void>;
    verifyEmail(token: string): Promise<VerifyResponse>;
    resendVerification(email: string): Promise<MessageResponse>;
    forgotPassword(email: string): Promise<MessageResponse>;
    startPasswordReset(email: string): Promise<OtpChallenge>;
    resendPasswordResetOtp(challengeId: string): Promise<OtpChallenge>;
    resetPasswordWithOtp(challengeId: string, code: string, newPassword: string): Promise<MessageResponse>;
    resetPassword(token: string, newPassword: string): Promise<MessageResponse>;
    getUser(): Promise<AuthUser | null>;
    getApplicationBranding(): Promise<ApplicationBranding>;
    getSessions(): Promise<AuthSession[]>;
    revokeSession(sessionId: string): Promise<void>;
    mfaStatus(): Promise<MfaStatus>;
    private request;
}
