import type { NextRequest } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const ALLOWED_UPSTREAM_PATHS = new Set([
  'oauth/token',
  'oauth/logout',
  'token/refresh',
  'token/verify',
  'token/session-check',
  'token/session-stream',
]);

const ACCESS_COOKIE = '__auth_access_token';
const REFRESH_COOKIE = '__auth_refresh_token';

function resolveAuthServer(): string {
  const raw =
    process.env.AUTH_SERVER_URL ||
    process.env.NEXT_PUBLIC_AUTH_SERVER ||
    '';
  return String(raw).trim().replace(/\/+$/, '');
}

function normalizeUpstreamPath(parts: string[] | undefined): string {
  return (parts || [])
    .map((part) => String(part || '').trim())
    .filter(Boolean)
    .join('/');
}

function buildTargetUrl(
  authServer: string,
  request: NextRequest,
  upstreamPath: string,
  accessToken?: string,
): string {
  const base = new URL(authServer);
  const source = new URL(request.url);
  base.pathname = `/${upstreamPath}`;
  base.search = source.search;

  if (
    upstreamPath === 'token/session-stream' &&
    !base.searchParams.get('token') &&
    accessToken
  ) {
    base.searchParams.set('token', accessToken);
  }

  return base.toString();
}

function shouldUseSecureCookie(request: NextRequest): boolean {
  return request.nextUrl.protocol === 'https:' || process.env.NODE_ENV === 'production';
}

function jwtMaxAge(token: string | undefined): number | null {
  if (!token) return null;
  try {
    const parts = token.split('.');
    if (parts.length < 2) return null;
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
    const payload = JSON.parse(Buffer.from(padded, 'base64').toString('utf-8')) as { exp?: number };
    if (!payload.exp || !Number.isFinite(payload.exp)) return null;
    const ttl = Math.floor(payload.exp - Date.now() / 1000);
    return ttl > 0 ? ttl : 0;
  } catch {
    return null;
  }
}

function serializeCookie(
  request: NextRequest,
  name: string,
  value: string,
  maxAge: number,
): string {
  const segments = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${Math.max(0, Math.floor(maxAge))}`,
  ];

  if (shouldUseSecureCookie(request)) {
    segments.push('Secure');
  }

  return segments.join('; ');
}

function serializeExpiredCookie(request: NextRequest, name: string): string {
  const segments = [
    `${name}=`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=0',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
  ];

  if (shouldUseSecureCookie(request)) {
    segments.push('Secure');
  }

  return segments.join('; ');
}

function makeJsonResponse(status: number, payload: unknown): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      'x-auth-proxy': 'next-app',
    },
  });
}

async function buildOutgoingBody(
  request: NextRequest,
  upstreamPath: string,
  accessToken: string | undefined,
  refreshToken: string | undefined,
): Promise<{ body?: string; contentType?: string; error?: Response }> {
  const method = request.method.toUpperCase();
  if (method === 'GET' || method === 'HEAD') {
    return {};
  }

  const contentType = request.headers.get('content-type') || '';
  const rawBody = await request.text();

  const expectsJsonPatch =
    upstreamPath === 'token/refresh' ||
    upstreamPath === 'token/verify' ||
    upstreamPath === 'token/session-check';

  if (!expectsJsonPatch) {
    return { body: rawBody || undefined, contentType: contentType || undefined };
  }

  let parsed: Record<string, unknown> = {};
  if (rawBody.trim()) {
    try {
      parsed = JSON.parse(rawBody) as Record<string, unknown>;
    } catch {
      return { error: makeJsonResponse(400, { detail: 'Invalid JSON request body' }) };
    }
  }

  if (upstreamPath === 'token/refresh' && !parsed.refresh_token) {
    parsed.refresh_token = refreshToken || '';
  }

  if (upstreamPath === 'token/verify' && !parsed.token) {
    parsed.token = accessToken || '';
  }

  if (upstreamPath === 'token/session-check' && !parsed.access_token) {
    parsed.access_token = accessToken || '';
  }

  if (
    (upstreamPath === 'token/refresh' && !parsed.refresh_token) ||
    (upstreamPath === 'token/verify' && !parsed.token) ||
    (upstreamPath === 'token/session-check' && !parsed.access_token)
  ) {
    return {
      error: makeJsonResponse(401, {
        detail: 'Missing session token cookie. Please log in again.',
      }),
    };
  }

  return {
    body: JSON.stringify(parsed),
    contentType: 'application/json',
  };
}

function buildForwardHeaders(request: NextRequest, contentType?: string): Headers {
  const outgoingHeaders = new Headers();
  request.headers.forEach((value, key) => {
    const lower = key.toLowerCase();
    if (
      lower === 'host' ||
      lower === 'connection' ||
      lower === 'content-length' ||
      lower === 'cookie'
    ) {
      return;
    }
    outgoingHeaders.set(key, value);
  });

  if (contentType) {
    outgoingHeaders.set('content-type', contentType);
  }

  return outgoingHeaders;
}

async function proxyRequest(
  request: NextRequest,
  context: { params: Promise<{ path?: string[] }> },
): Promise<Response> {
  const authServer = resolveAuthServer();
  if (!authServer) {
    return makeJsonResponse(500, {
      detail: 'Auth proxy is not configured. Set AUTH_SERVER_URL or NEXT_PUBLIC_AUTH_SERVER.',
    });
  }

  const params = await context.params;
  const upstreamPath = normalizeUpstreamPath(params.path);
  if (!ALLOWED_UPSTREAM_PATHS.has(upstreamPath)) {
    return makeJsonResponse(404, { detail: 'Unsupported auth proxy path' });
  }

  const accessCookie = request.cookies.get(ACCESS_COOKIE)?.value;
  const refreshCookie = request.cookies.get(REFRESH_COOKIE)?.value;

  const bodySpec = await buildOutgoingBody(request, upstreamPath, accessCookie, refreshCookie);
  if (bodySpec.error) {
    return bodySpec.error;
  }

  const target = buildTargetUrl(authServer, request, upstreamPath, accessCookie);
  const method = request.method.toUpperCase();

  try {
    const upstreamResponse = await fetch(target, {
      method,
      headers: buildForwardHeaders(request, bodySpec.contentType),
      body: bodySpec.body,
      redirect: 'manual',
      cache: 'no-store',
    });

    // SSE should remain streaming and untouched except minimal proxy headers.
    if (upstreamPath === 'token/session-stream') {
      const streamHeaders = new Headers(upstreamResponse.headers);
      streamHeaders.delete('content-length');
      streamHeaders.delete('set-cookie');
      streamHeaders.set('x-auth-proxy', 'next-app');
      streamHeaders.set('cache-control', 'no-store');

      return new Response(upstreamResponse.body, {
        status: upstreamResponse.status,
        headers: streamHeaders,
      });
    }

    const raw = await upstreamResponse.text();
    let parsed: Record<string, unknown> | null = null;
    try {
      parsed = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
    } catch {
      parsed = null;
    }

    const responseHeaders = new Headers();
    responseHeaders.set('x-auth-proxy', 'next-app');
    responseHeaders.set('cache-control', 'no-store');

    if (parsed && typeof parsed === 'object') {
      responseHeaders.set('content-type', 'application/json');
    } else if (upstreamResponse.headers.get('content-type')) {
      responseHeaders.set('content-type', upstreamResponse.headers.get('content-type') || 'text/plain');
    }

    // Successful token issuance/refresh: store tokens in HttpOnly cookies and scrub response body.
    if (
      upstreamResponse.ok &&
      parsed &&
      (upstreamPath === 'oauth/token' || upstreamPath === 'token/refresh')
    ) {
      const nextPayload: Record<string, unknown> = { ...(parsed || {}) };
      const accessToken = String(nextPayload.access_token || '');
      const refreshToken = String(nextPayload.refresh_token || '');

      if (accessToken) {
        const accessMaxAge = jwtMaxAge(accessToken) ?? 900;
        responseHeaders.append('set-cookie', serializeCookie(request, ACCESS_COOKIE, accessToken, accessMaxAge));
      }

      if (refreshToken) {
        const refreshMaxAge = jwtMaxAge(refreshToken) ?? 7 * 24 * 60 * 60;
        responseHeaders.append('set-cookie', serializeCookie(request, REFRESH_COOKIE, refreshToken, refreshMaxAge));
      }

      delete nextPayload.access_token;
      delete nextPayload.refresh_token;
      nextPayload.authenticated = true;

      return new Response(JSON.stringify(nextPayload), {
        status: upstreamResponse.status,
        headers: responseHeaders,
      });
    }

    // Logout should always clear proxy-side auth cookies.
    if (upstreamPath === 'oauth/logout') {
      responseHeaders.append('set-cookie', serializeExpiredCookie(request, ACCESS_COOKIE));
      responseHeaders.append('set-cookie', serializeExpiredCookie(request, REFRESH_COOKIE));
    }

    // Refresh failure should clear cookies so client can force fresh login.
    if (!upstreamResponse.ok && upstreamPath === 'token/refresh') {
      responseHeaders.append('set-cookie', serializeExpiredCookie(request, ACCESS_COOKIE));
      responseHeaders.append('set-cookie', serializeExpiredCookie(request, REFRESH_COOKIE));
    }

    if (parsed && typeof parsed === 'object') {
      return new Response(JSON.stringify(parsed), {
        status: upstreamResponse.status,
        headers: responseHeaders,
      });
    }

    return new Response(raw, {
      status: upstreamResponse.status,
      headers: responseHeaders,
    });
  } catch (error) {
    return makeJsonResponse(502, {
      detail: 'Auth server is unreachable from proxy',
      target,
      error: error instanceof Error ? error.message : 'Unknown proxy error',
    });
  }
}

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ path?: string[] }> },
): Promise<Response> {
  return proxyRequest(request, context);
}

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ path?: string[] }> },
): Promise<Response> {
  return proxyRequest(request, context);
}

export async function PUT(
  request: NextRequest,
  context: { params: Promise<{ path?: string[] }> },
): Promise<Response> {
  return proxyRequest(request, context);
}

export async function DELETE(
  request: NextRequest,
  context: { params: Promise<{ path?: string[] }> },
): Promise<Response> {
  return proxyRequest(request, context);
}

export async function OPTIONS(
  request: NextRequest,
  context: { params: Promise<{ path?: string[] }> },
): Promise<Response> {
  return proxyRequest(request, context);
}
