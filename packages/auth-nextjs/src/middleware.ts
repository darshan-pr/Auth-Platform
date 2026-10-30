import { NextRequest, NextResponse } from "next/server";
import { AuthNextOptions, cookieNames, isSecureRequest } from "./config.js";

export interface MiddlewareOptions extends AuthNextOptions {
  signInUrl?: string;
  matcher?: (pathname: string) => boolean;
}

function localSignInUrl(value: string): string {
  return value.startsWith("/") && !value.startsWith("//") ? value : "/sign-in";
}

/** Allows auth refresh when either HttpOnly session cookie remains; server helpers remain authoritative. */
export function createMiddleware(options: MiddlewareOptions = {}) {
  const signInUrl = localSignInUrl(options.signInUrl ?? "/sign-in");
  return function authMiddleware(request: NextRequest): NextResponse {
    if (options.matcher && !options.matcher(request.nextUrl.pathname)) return NextResponse.next();
    const names = cookieNames(isSecureRequest(request.url));
    const hasAccessToken = Boolean(request.cookies.get(names.access)?.value);
    const hasRefreshToken = Boolean(request.cookies.get(names.refresh)?.value);
    if (hasAccessToken || hasRefreshToken) return NextResponse.next();
    const target = request.nextUrl.clone();
    target.pathname = signInUrl;
    target.searchParams.set("returnTo", request.nextUrl.pathname);
    return NextResponse.redirect(target);
  };
}
