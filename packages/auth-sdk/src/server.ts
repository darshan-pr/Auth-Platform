/**
 * ============================================================
 *  Auth Platform SDK — Server Proxy  (v3.1.0)
 * ============================================================
 *
 *  Server-side BFF proxy for Next.js route handlers.
 *  Handles everything the browser must NOT touch:
 *    • client_secret injection (backend-to-backend)
 *    • HttpOnly cookie storage for tokens
 *    • Token scrubbing from response bodies
 *    • Cookie cleanup on logout/revocation
 *
 *  Usage:
 *    import { createAuthProxy } from 'auth-platform-sdk/server';
 *
 *    const handler = createAuthProxy();
 *    export const GET  = handler;
 *    export const POST = handler;
 *
 * ============================================================
 */

import type { NextRequest } from 'next/server';


// ─── Types ──────────────────────────────────────────────────

export interface AuthProxyOptions {
  /** Auth server URL (default: reads AUTH_SERVER_URL or NEXT_PUBLIC_AUTH_SERVER env) */
  authServerUrl?: string;
  /** Client secret (default: reads AUTH_CLIENT_SECRET env) */
  clientSecret?: string;
}

export type AuthProxyHandler = (
  request: NextRequest,
  context: { params: Promise<{ path?: string[] }> },
) => Promise<Response>;


// ─── Constants ──────────────────────────────────────────────

const ACCESS_COOKIE  = '__auth_access_token';
const REFRESH_COOKIE = '__auth_refresh_token';

const ALLOWED_PATHS = new Set([
  'oauth/token', 'oauth/logout',
  'token/refresh', 'token/verify', 'token/revoke',
  'token/session-check', 'token/session-stream',
]);

const ENRICHED_PATHS = new Set([
  'oauth/token', 'token/refresh', 'token/verify', 'token/session-check',
]);

const TOKEN_PATHS = new Set(['oauth/token', 'token/refresh']);
const CLEAR_PATHS = new Set(['oauth/logout', 'token/revoke']);


// ─── Helpers ────────────────────────────────────────────────

function _json(status: number, data: Record<string, unknown>): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
}

function _jwtMaxAge(token: string): number | null {
  if (!token) return null;
  try {
    const b64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    const payload = JSON.parse(Buffer.from(padded, 'base64').toString());
    const ttl = Math.floor(payload.exp - Date.now() / 1000);
    return ttl > 0 ? ttl : 0;
  } catch { return null; }
}

function _cookie(request: NextRequest, name: string, value: string, maxAge: number): string {
  const secure = request.nextUrl?.protocol === 'https:' || process.env.NODE_ENV === 'production';
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/', 'HttpOnly', 'SameSite=Lax',
    `Max-Age=${Math.max(0, Math.floor(maxAge))}`,
  ];
  if (secure) parts.push('Secure');
  return parts.join('; ');
}

function _clearCookie(request: NextRequest, name: string): string {
  const secure = request.nextUrl?.protocol === 'https:' || process.env.NODE_ENV === 'production';
  const parts = [
    `${name}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax',
    'Max-Age=0', 'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
  ];
  if (secure) parts.push('Secure');
  return parts.join('; ');
}


// ─── Body Builder ───────────────────────────────────────────

interface BodySpec {
  body?: string;
  contentType?: string;
  error?: Response;
}

async function _buildBody(
  request: NextRequest,
  path: string,
  accessToken: string | undefined,
  refreshToken: string | undefined,
  clientSecret: string,
): Promise<BodySpec> {
  if (request.method === 'GET' || request.method === 'HEAD') return {};

  const raw = await request.text();

  if (!ENRICHED_PATHS.has(path)) {
    return { body: raw || undefined, contentType: request.headers.get('content-type') || undefined };
  }

  let parsed: Record<string, unknown> = {};
  if (raw.trim()) {
    try { parsed = JSON.parse(raw); }
    catch { return { error: _json(400, { detail: 'Invalid JSON body' }) }; }
  }

  // ═══ CORE SECURITY LOGIC ═══════════════════════════════
  // This is the entire reason the proxy exists.

  // 1. Token exchange: inject client_secret (RFC 6749 §2.3.1)
  //    FAIL-CLOSED: no secret → hard error, not silent skip
  if (path === 'oauth/token') {
    if (!clientSecret) {
      return { error: _json(500, {
        detail: 'AUTH_CLIENT_SECRET is not configured. Set it in .env.local (server-side only). Get it from Admin Console → Credentials.',
      })};
    }
    parsed.client_secret = clientSecret;
  }

  // 2. Refresh: inject refresh_token from HttpOnly cookie
  if (path === 'token/refresh' && !parsed.refresh_token) {
    parsed.refresh_token = refreshToken || '';
  }

  // 3. Verify: inject access_token from HttpOnly cookie
  if (path === 'token/verify' && !parsed.token) {
    parsed.token = accessToken || '';
  }

  // 4. Session check: inject access_token from HttpOnly cookie
  if (path === 'token/session-check' && !parsed.access_token) {
    parsed.access_token = accessToken || '';
  }

  // Validate required tokens
  if (
    (path === 'token/refresh' && !parsed.refresh_token) ||
    (path === 'token/verify' && !parsed.token) ||
    (path === 'token/session-check' && !parsed.access_token)
  ) {
    return { error: _json(401, { detail: 'No session. Please log in.' }) };
  }

  return { body: JSON.stringify(parsed), contentType: 'application/json' };
}


// ─── Public API ─────────────────────────────────────────────

/**
 * Create a Next.js route handler that securely proxies auth requests.
 *
 * @example
 *   // app/api/auth/[...path]/route.ts
 *   import { createAuthProxy } from 'auth-platform-sdk/server';
 *
 *   const handler = createAuthProxy();
 *   export const GET  = handler;
 *   export const POST = handler;
 *   export const dynamic = 'force-dynamic';
 */
export function createAuthProxy(options: AuthProxyOptions = {}): AuthProxyHandler {
  const authServer = String(
    options.authServerUrl || process.env.AUTH_SERVER_URL || process.env.NEXT_PUBLIC_AUTH_SERVER || '',
  ).trim().replace(/\/+$/, '');

  const clientSecret = String(
    options.clientSecret || process.env.AUTH_CLIENT_SECRET || '',
  ).trim();

  if (!authServer) console.error('[AuthProxy] No auth server URL configured.');

  return async function handler(request, context) {
    if (!authServer) return _json(500, { detail: 'Auth server URL not configured.' });

    const params = await context.params;
    const path = (params.path || []).filter(Boolean).join('/');

    if (!ALLOWED_PATHS.has(path)) return _json(404, { detail: 'Unknown auth path' });

    const accessToken  = request.cookies.get(ACCESS_COOKIE)?.value;
    const refreshToken = request.cookies.get(REFRESH_COOKIE)?.value;

    const spec = await _buildBody(request, path, accessToken, refreshToken, clientSecret);
    if (spec.error) return spec.error;

    // Build target URL
    const target = new URL(authServer);
    target.pathname = `/${path}`;
    target.search = new URL(request.url).search;
    if (path === 'token/session-stream' && accessToken) {
      target.searchParams.set('token', accessToken);
    }

    try {
      // Forward headers (strip host/cookie)
      const headers = new Headers();
      request.headers.forEach((v, k) => {
        if (!['host', 'connection', 'content-length', 'cookie'].includes(k.toLowerCase())) headers.set(k, v);
      });
      if (spec.contentType) headers.set('content-type', spec.contentType);

      const upstream = await fetch(target.toString(), {
        method: request.method,
        headers,
        body: spec.body,
        redirect: 'manual',
        cache: 'no-store',
      });

      // SSE: pass through
      if (path === 'token/session-stream') {
        const h = new Headers(upstream.headers);
        h.delete('content-length');
        h.delete('set-cookie');
        return new Response(upstream.body, { status: upstream.status, headers: h });
      }

      const raw = await upstream.text();
      let parsed: Record<string, unknown> | null = null;
      try { parsed = raw ? JSON.parse(raw) : {}; } catch { parsed = null; }

      const resHeaders = new Headers();
      resHeaders.set('cache-control', 'no-store');
      resHeaders.set('content-type', parsed ? 'application/json' : (upstream.headers.get('content-type') || 'text/plain'));

      // Token issuance → store in HttpOnly cookies, scrub from body
      if (upstream.ok && parsed && TOKEN_PATHS.has(path)) {
        const scrubbed = { ...parsed };

        if (typeof scrubbed.access_token === 'string') {
          resHeaders.append('set-cookie', _cookie(request, ACCESS_COOKIE, scrubbed.access_token, _jwtMaxAge(scrubbed.access_token) ?? 900));
        }
        if (typeof scrubbed.refresh_token === 'string') {
          resHeaders.append('set-cookie', _cookie(request, REFRESH_COOKIE, scrubbed.refresh_token, _jwtMaxAge(scrubbed.refresh_token) ?? 604800));
        }

        delete scrubbed.access_token;
        delete scrubbed.refresh_token;
        scrubbed.authenticated = true;

        return new Response(JSON.stringify(scrubbed), { status: upstream.status, headers: resHeaders });
      }

      // Cookie clearing on logout/revoke/failed-refresh
      if (CLEAR_PATHS.has(path) || (!upstream.ok && path === 'token/refresh')) {
        resHeaders.append('set-cookie', _clearCookie(request, ACCESS_COOKIE));
        resHeaders.append('set-cookie', _clearCookie(request, REFRESH_COOKIE));
      }

      return new Response(parsed ? JSON.stringify(parsed) : raw, { status: upstream.status, headers: resHeaders });

    } catch (e: unknown) {
      return _json(502, { detail: 'Auth server unreachable', error: e instanceof Error ? e.message : String(e) });
    }
  };
}
