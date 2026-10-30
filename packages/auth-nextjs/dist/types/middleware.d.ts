import { NextRequest, NextResponse } from "next/server";
import { AuthNextOptions } from "./config.js";
export interface MiddlewareOptions extends AuthNextOptions {
    signInUrl?: string;
    matcher?: (pathname: string) => boolean;
}
/** Allows auth refresh when either HttpOnly session cookie remains; server helpers remain authoritative. */
export declare function createMiddleware(options?: MiddlewareOptions): (request: NextRequest) => NextResponse;
