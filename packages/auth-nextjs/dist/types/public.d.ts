import type { AuthUser } from "@authplatform/auth-core";
type Payload = Record<string, unknown>;
type PublicPayload = Payload | Payload[];
export declare function publicUser(value: unknown): AuthUser | null;
export declare function publicSuccess(path: string, value: unknown): PublicPayload;
export declare function publicLogin(value: unknown): Payload;
export {};
