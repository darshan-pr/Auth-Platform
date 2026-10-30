import "server-only";
import { type AuthUser } from "@authplatform/auth-core";
import { AuthNextOptions } from "./config.js";
export interface AuthResult {
    isAuthenticated: boolean;
    user: AuthUser | null;
}
export declare function auth(options?: AuthNextOptions): Promise<AuthResult>;
export declare function currentUser(options?: AuthNextOptions): Promise<AuthUser | null>;
export declare class AuthRequiredError extends Error {
    constructor();
}
export declare function requireAuth(options?: AuthNextOptions): Promise<AuthUser>;
