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
export declare function resolveConfig(options?: AuthNextOptions): AuthConfig;
export declare const ACCESS_COOKIE = "authplatform_sdk_access";
export declare const REFRESH_COOKIE = "authplatform_sdk_refresh";
export declare const CSRF_COOKIE = "authplatform_csrf";
export declare function cookieNames(secure: boolean): {
    access: string;
    refresh: string;
};
export declare function isSecureRequest(requestUrl?: string): boolean;
