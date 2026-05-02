'use client';
/**
 * ============================================================
 *  Auth Platform SDK — Client  (v3.1.0)
 * ============================================================
 *
 *  Browser-side OAuth 2.0 + PKCE client with React integration.
 *
 *  Install:
 *    npm install auth-platform-sdk
 *
 *  Usage:
 *    import { AuthProvider, useAuth } from 'auth-platform-sdk/client';
 *
 *  Setup (.env.local):
 *    NEXT_PUBLIC_AUTH_SERVER=https://auth.example.com
 *    NEXT_PUBLIC_CLIENT_ID=your-client-id
 *    NEXT_PUBLIC_REDIRECT_URI=http://localhost:3000/callback
 *
 * ============================================================
 */

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';


// ─── Types ──────────────────────────────────────────────────

export interface AuthUser {
  sub: string;
  email: string;
  user_id: number;
  app_id: string;
  scope: string | null;
  issuer: string;
  expires_at: Date;
  issued_at: Date;
}

export interface AuthClientConfig {
  /** Auth server URL */
  authServer: string;
  /** OAuth Client ID */
  clientId: string;
  /** OAuth Callback URL (must match Admin Console) */
  redirectUri: string;
  /** Proxy route path (default: '/api/auth') */
  proxyPath?: string;
  /** OAuth scope (default: 'openid profile email') */
  scope?: string;
  // Legacy aliases
  AUTH_SERVER?: string;
  CLIENT_ID?: string;
  REDIRECT_URI?: string;
  AUTH_PROXY_PATH?: string;
  SCOPE?: string;
}

export interface AuthContextValue {
  isAuthenticated: boolean;
  user: AuthUser | null;
  login: (options?: LoginOptions) => void;
  logout: () => void;
  loading: boolean;
  logoutReason: string | null;
  authClient: AuthClient | null;
}

export interface LoginOptions {
  prompt?: string;
  loginHint?: string;
}


// ─── Helpers ────────────────────────────────────────────────

function clean(v: unknown): string {
  return v == null ? '' : String(v).trim().replace(/^['"]|['"]$/g, '');
}

function randomBase64Url(bytes: number): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  let s = '';
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sha256Base64Url(plain: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(plain));
  const arr = new Uint8Array(digest);
  let s = '';
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}


// ═══════════════════════════════════════════════════════════
//  AuthClient — Browser-side OAuth client
// ═══════════════════════════════════════════════════════════

export class AuthClient {
  #authServer: string;
  #proxyPath: string;
  #clientId: string;
  #redirectUri: string;
  #scope: string;
  #sessionPayload: Record<string, unknown> | null = null;
  #onAuthChangeCb: ((isAuth: boolean, reason?: string | null) => void) | null = null;
  #sessionInterval: ReturnType<typeof setInterval> | null = null;
  #eventSource: EventSource | null = null;

  constructor(config: AuthClientConfig) {
    // Accept both camelCase (new) and UPPER_CASE (legacy) keys
    this.#authServer  = clean(config.authServer || config.AUTH_SERVER).replace(/\/+$/, '');
    this.#clientId    = clean(config.clientId || config.CLIENT_ID);
    this.#redirectUri = clean(config.redirectUri || config.REDIRECT_URI);
    this.#proxyPath   = clean(config.proxyPath || config.AUTH_PROXY_PATH || '/api/auth').replace(/\/+$/, '');
    this.#scope       = clean(config.scope || config.SCOPE) || 'openid profile email';

    if (!this.#authServer) {
      throw new Error('[AuthSDK] authServer is required. Check your .env.local');
    }
  }


  // ─── Public API ─────────────────────────────────────────

  /** Redirect to the Auth Platform hosted login page. */
  login(options: LoginOptions = {}): void {
    if (!this.#clientId) throw new Error('[AuthSDK] clientId is not configured.');
    if (!this.#redirectUri) throw new Error('[AuthSDK] redirectUri is not configured.');
    this.#startOAuthFlow(options);
  }

  /** Clear session and cookies, fire auth change callback. */
  logout(reason?: string): void {
    const redirect = encodeURIComponent(window.location.origin);

    // Clear HttpOnly cookies via proxy
    this.#fetch(`/oauth/logout?post_logout_redirect_uri=${redirect}`, { method: 'GET' }).catch(() => {});

    // Clear SSO cookie directly
    try {
      const img = new Image();
      img.src = `${this.#authServer}/oauth/logout?post_logout_redirect_uri=${redirect}`;
    } catch { /* ignore */ }

    this.#clearSession();
    this.#onAuthChangeCb?.(false, reason || null);
  }

  /** Whether the user has a valid (non-expired) session. */
  isAuthenticated(): boolean {
    const exp = this.#sessionPayload?.exp;
    return Boolean(exp && typeof exp === 'number' && exp * 1000 > Date.now());
  }

  /** Current user info (frozen, immutable). */
  getUser(): AuthUser | null {
    const p = this.#sessionPayload;
    if (!p) return null;
    try {
      return Object.freeze({
        sub:        String(p.sub ?? ''),
        email:      String(p.email ?? p.sub ?? ''),
        user_id:    Number(p.user_id ?? 0),
        app_id:     String(p.app_id ?? ''),
        scope:      p.scope ? String(p.scope) : null,
        issuer:     String(p.iss ?? ''),
        expires_at: new Date(Number(p.exp) * 1000),
        issued_at:  new Date(Number(p.iat) * 1000),
      });
    } catch { return null; }
  }

  /**
   * Access token is stored in HttpOnly cookies — browser can't read it.
   * Use the proxy for authenticated API calls.
   */
  getAccessToken(): null { return null; }

  /** Refresh the access token using HttpOnly refresh_token cookie. */
  async refreshAccessToken(): Promise<boolean> {
    try {
      const res = await this.#fetch('/token/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (res.ok) return Boolean(await this.verifyToken());
    } catch (e: unknown) {
      console.error('[AuthSDK] Refresh failed:', e instanceof Error ? e.message : e);
    }
    this.#clearSession();
    return false;
  }

  /** Verify the current access token with the auth server. */
  async verifyToken(): Promise<Record<string, unknown> | null> {
    try {
      const res = await this.#fetch('/token/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (!res.ok) return null;
      const data = await res.json();
      const payload = data?.payload || data;
      if (!payload || typeof payload !== 'object') return null;
      this.#sessionPayload = payload;
      return payload;
    } catch (e: unknown) {
      console.error('[AuthSDK] Verify failed:', e instanceof Error ? e.message : e);
      this.#sessionPayload = null;
      return null;
    }
  }

  /** Restore session from HttpOnly cookies (call on page load). */
  async restoreSession(): Promise<boolean> {
    const payload = await this.verifyToken();
    if (payload) {
      this.#startSessionMonitor();
      this.#startSessionStream();
      return true;
    }
    this.#clearSession();
    return false;
  }

  /**
   * Handle OAuth callback — call this on page load.
   * Exchanges the authorization code for tokens via the proxy.
   */
  async handleCallback(): Promise<boolean> {
    const params = new URLSearchParams(window.location.search);
    const code  = params.get('code');
    const state = params.get('state');
    if (!code || !state) return false;

    // CSRF check
    if (state !== sessionStorage.getItem('_auth_state')) {
      console.error('[AuthSDK] State mismatch — possible CSRF');
      this.#cleanup();
      return false;
    }

    const codeVerifier = sessionStorage.getItem('_auth_code_verifier');
    if (!codeVerifier) {
      console.error('[AuthSDK] Missing PKCE code_verifier');
      this.#cleanup();
      return false;
    }

    // Remove sensitive params from URL bar
    window.history.replaceState({}, document.title, window.location.pathname);
    this.#cleanup();

    // Validate code format
    if (!/^[A-Za-z0-9_-]{20,}$/.test(code)) {
      console.error('[AuthSDK] Invalid authorization code format');
      return false;
    }

    try {
      const res = await this.#fetch('/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          grant_type:    'authorization_code',
          code,
          client_id:     this.#clientId,
          redirect_uri:  this.#redirectUri,
          code_verifier: codeVerifier,
          // client_secret is injected server-side by the proxy
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        console.error('[AuthSDK] Token exchange failed:', err.detail || res.status);
        return false;
      }

      const restored = await this.restoreSession();
      if (restored) this.#onAuthChangeCb?.(true);
      return restored;
    } catch (e: unknown) {
      console.error('[AuthSDK] Token exchange error:', e instanceof Error ? e.message : e);
      return false;
    }
  }

  /** Register a callback for login/logout events. */
  onAuthChange(callback: (isAuth: boolean, reason?: string | null) => void): void {
    this.#onAuthChangeCb = callback;
  }

  /** Start auto-refresh and real-time revocation monitoring. */
  startAutoRefresh(): void {
    this.#startSessionMonitor();
    this.#startSessionStream();
  }

  /** Seconds until the access token expires. */
  getTimeUntilExpiry(): number {
    const exp = this.#sessionPayload?.exp;
    if (!exp || typeof exp !== 'number') return 0;
    return Math.max(0, Math.floor((exp * 1000 - Date.now()) / 1000));
  }


  // ─── Private: OAuth Flow ────────────────────────────────

  async #startOAuthFlow(options: LoginOptions): Promise<void> {
    const codeVerifier  = randomBase64Url(64);
    const codeChallenge = await sha256Base64Url(codeVerifier);
    const state         = randomBase64Url(16);

    sessionStorage.setItem('_auth_code_verifier', codeVerifier);
    sessionStorage.setItem('_auth_state', state);

    const qs = new URLSearchParams({
      client_id:             this.#clientId,
      redirect_uri:          this.#redirectUri,
      response_type:         'code',
      state,
      scope:                 this.#scope,
      code_challenge:        codeChallenge,
      code_challenge_method: 'S256',
    });
    if (options.prompt)    qs.set('prompt', options.prompt);
    if (options.loginHint) qs.set('login_hint', options.loginHint);

    window.location.href = `${this.#authServer}/oauth/authorize?${qs}`;
  }

  #clearSession(): void {
    this.#sessionPayload = null;
    this.#stopMonitor();
    this.#stopStream();
  }

  #cleanup(): void {
    sessionStorage.removeItem('_auth_code_verifier');
    sessionStorage.removeItem('_auth_state');
  }


  // ─── Private: Auto-Refresh ──────────────────────────────

  #startSessionMonitor(): void {
    this.#stopMonitor();
    this.#sessionInterval = setInterval(async () => {
      const ttl = this.getTimeUntilExpiry();
      if (ttl <= 0) {
        if (!(await this.refreshAccessToken())) this.logout('session_expired');
      } else if (ttl < 120) {
        await this.refreshAccessToken();
      }
    }, 15_000);
  }

  #stopMonitor(): void {
    if (this.#sessionInterval) { clearInterval(this.#sessionInterval); this.#sessionInterval = null; }
  }


  // ─── Private: SSE Revocation Stream ─────────────────────

  #startSessionStream(): void {
    this.#stopStream();
    if (!this.isAuthenticated() || typeof EventSource === 'undefined') return;

    this.#eventSource = new EventSource(`${this.#proxyPath}/token/session-stream`);

    this.#eventSource.addEventListener('revoked', () => {
      this.#stopStream();
      this.logout('revoked_by_admin');
    });

    this.#eventSource.onerror = async () => {
      if (this.#eventSource?.readyState === EventSource.CLOSED) {
        this.#stopStream();
        if (await this.refreshAccessToken()) setTimeout(() => this.#startSessionStream(), 2000);
        else this.logout('session_expired');
      }
    };
  }

  #stopStream(): void {
    if (this.#eventSource) { this.#eventSource.close(); this.#eventSource = null; }
  }


  // ─── Private: Networking ────────────────────────────────

  /**
   * ALL requests go through the proxy — no fallback.
   * The proxy is the security boundary.
   */
  #fetch(path: string, init?: RequestInit): Promise<Response> {
    const p = path.startsWith('/') ? path : `/${path}`;
    return fetch(`${this.#proxyPath}${p}`, { credentials: 'include', ...init });
  }
}


// ═══════════════════════════════════════════════════════════
//  React Integration — AuthProvider + useAuth()
// ═══════════════════════════════════════════════════════════

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

/**
 * AuthProvider — wrap your app to enable authentication.
 *
 * Reads config from NEXT_PUBLIC_* environment variables automatically.
 *
 * @example
 *   // layout.tsx
 *   import { AuthProvider } from 'auth-platform-sdk/client';
 *   <AuthProvider>{children}</AuthProvider>
 */
export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [client, setClient]   = useState<AuthClient | null>(null);
  const [isAuth, setIsAuth]   = useState(false);
  const [user, setUser]       = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [reason, setReason]   = useState<string | null>(null);

  useEffect(() => {
    const init = async () => {
      try {
        const c = new AuthClient({
          authServer:  process.env.NEXT_PUBLIC_AUTH_SERVER || '',
          clientId:    process.env.NEXT_PUBLIC_CLIENT_ID || '',
          redirectUri: process.env.NEXT_PUBLIC_REDIRECT_URI || '',
          proxyPath:   process.env.NEXT_PUBLIC_AUTH_PROXY_PATH || '/api/auth',
          scope:       process.env.NEXT_PUBLIC_AUTH_SCOPE,
        });
        setClient(c);

        const handled = await c.handleCallback();
        let authenticated = c.isAuthenticated();
        if (!authenticated && !handled) {
          authenticated = await c.restoreSession();
        }

        setIsAuth(authenticated);
        if (authenticated) {
          setUser(c.getUser());
          if (!handled) c.startAutoRefresh();
        }

        c.onAuthChange((authed, logoutReason) => {
          setIsAuth(authed);
          if (authed) { setUser(c.getUser()); setReason(null); }
          else { setUser(null); if (logoutReason) setReason(logoutReason); }
        });
      } catch (e) {
        console.error('[AuthSDK] Init failed:', e);
      } finally {
        setLoading(false);
      }
    };
    init();
  }, []);

  const login  = useCallback((opts?: LoginOptions) => client?.login(opts ?? {}), [client]);
  const logout = useCallback(() => { client?.logout(); setUser(null); setIsAuth(false); setReason(null); }, [client]);

  return (
    <AuthContext.Provider value={{ isAuthenticated: isAuth, user, login, logout, loading, logoutReason: reason, authClient: client }}>
      {children}
    </AuthContext.Provider>
  );
}

/**
 * useAuth() — access auth state in any component.
 *
 * @example
 *   import { useAuth } from 'auth-platform-sdk/client';
 *   const { user, login, logout, isAuthenticated, loading } = useAuth();
 */
export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (ctx === undefined) throw new Error('useAuth() must be inside <AuthProvider>');
  return ctx;
}
