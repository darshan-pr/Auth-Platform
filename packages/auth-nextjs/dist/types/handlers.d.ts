import "server-only";
import { NextRequest, NextResponse } from "next/server.js";
import { AuthNextOptions } from "./config.js";
type RouteContext = {
    params: Promise<{
        path?: string[];
    }>;
};
type Handler = (request: NextRequest, context: RouteContext) => Promise<NextResponse>;
export declare function createAuthHandlers(options?: AuthNextOptions): Record<"GET" | "POST" | "PUT" | "PATCH" | "DELETE", Handler>;
export {};
