'use client';
/**
 * ============================================================
 *  Auth Platform — SDK  (v3.1.0)
 * ============================================================
 *
 *  Complete, secure authentication for Next.js apps.
 *  OAuth 2.0 Authorization Code Flow with PKCE + client_secret.
 *  Zero external dependencies.
 *
 *  This SDK has 2 parts:
 *    1. auth-sdk.js    — Browser-side (this file)
 *    2. auth-server.js — Server-side proxy (handles secrets & cookies)
 *
 *  ┌──────────────────────────────────────────────────────────┐
 *  │                    SETUP GUIDE                           │
 *  │                                                          │
 *  │  Step 1: Create .env.local                               │
 *  │  ────────────────────────────────────────                 │
 *  │    NEXT_PUBLIC_AUTH_SERVER=http://localhost:8000           │
 *  │    NEXT_PUBLIC_CLIENT_ID=<from Admin Console>             │
 *  │    NEXT_PUBLIC_REDIRECT_URI=http://localhost:3000/callback│
 *  │    AUTH_CLIENT_SECRET=<from Admin Console → Credentials>  │
 *  │                                                          │
 *  │  Step 2: Create the auth proxy route                     │
 *  │  ────────────────────────────────────────                 │
 *  │    File: app/api/auth/[...path]/route.ts                 │
 *  │                                                          │
 *  │    import { createAuthProxy } from '@/lib/auth-server';  │
 *  │    const handler = createAuthProxy();                    │
 *  │    export const GET = handler;                           │
 *  │    export const POST = handler;                          │
 *  │    export const dynamic = 'force-dynamic';               │
 *  │                                                          │
 *  │  Step 3: Wrap your app with AuthProvider                 │
 *  │  ────────────────────────────────────────                 │
 *  │    // In your layout.tsx:                                │
 *  │    import { AuthProvider } from '@/lib/auth-sdk';        │
 *  │    <AuthProvider>{children}</AuthProvider>               │
 *  │                                                          │
 *  │  Step 4: Use in any component                            │
 *  │  ────────────────────────────────────────                 │
 *  │    import { useAuth } from '@/lib/auth-sdk';             │
 *  │    const { user, login, logout } = useAuth();            │
 *  │                                                          │
 *  │  That's it. 4 steps. The SDK handles everything else.    │
 *  └──────────────────────────────────────────────────────────┘
 *
 *  Security architecture:
 *  ────────────────────────────────────────────────────────────
 *    Browser (this file)              Server (auth-server.js)
 *    ┌─────────────────────┐          ┌──────────────────────────┐
 *    │ PKCE (code_verifier) │  ────►  │ + client_secret injection │
 *    │ State (CSRF)         │          │ + HttpOnly cookie storage  │
 *    │ Login redirect       │          │ + Token body scrubbing     │
 *    │ Session monitoring   │          │ + Cookie cleanup on logout │
 *    └─────────────────────┘          └──────────────────────────┘
 *       has NO secrets                   has client_secret + tokens
 *       has NO tokens                    in HttpOnly cookies
 *
 * ============================================================
 */


/* ═══════════════════════════════════════════════════════════
 *  PART 1: AuthClient — Browser-side OAuth client
 * ═══════════════════════════════════════════════════════════ */

class AuthClient {

    #authServer;
    #proxyPath;
    #clientId;
    #redirectUri;
    #scope;
    #sessionPayload = null;
    #onAuthChangeCb = null;
    #sessionInterval = null;
    #eventSource = null;

    /**
     * Create an AuthClient instance.
     *
     * @param {Object} config
     * @param {string} config.authServer    - Auth server URL (alias: AUTH_SERVER)
     * @param {string} config.clientId      - OAuth Client ID (alias: CLIENT_ID)
     * @param {string} config.redirectUri   - Callback URL (alias: REDIRECT_URI)
     * @param {string} [config.proxyPath]   - Proxy route path (alias: AUTH_PROXY_PATH, default: '/api/auth')
     * @param {string} [config.scope]       - OAuth scope (alias: SCOPE, default: 'openid profile email')
     */
    constructor(config = {}) {
        const clean = (v) => v == null ? '' : String(v).trim().replace(/^['"]|['"]$/g, '');

        // Accept both camelCase (new) and UPPER_CASE (legacy) config keys
        this.#authServer = clean(config.authServer || config.AUTH_SERVER).replace(/\/+$/, '');
        this.#clientId   = clean(config.clientId || config.CLIENT_ID);
        this.#redirectUri = clean(config.redirectUri || config.REDIRECT_URI);
        this.#proxyPath  = clean(config.proxyPath || config.AUTH_PROXY_PATH || '/api/auth').replace(/\/+$/, '');
        this.#scope      = clean(config.scope || config.SCOPE) || 'openid profile email';

        if (!this.#authServer) {
            throw new Error('[AuthSDK] authServer is required. Check your .env.local');
        }
    }


    /* ─── Public API ─────────────────────────────────────── */

    /** Redirect to the Auth Platform hosted login page. */
    login(options = {}) {
        if (!this.#clientId) throw new Error('[AuthSDK] clientId is not configured.');
        if (!this.#redirectUri) throw new Error('[AuthSDK] redirectUri is not configured.');
        this.#startOAuthFlow(options);
    }

    /** Clear session, notify listeners, clear server-side cookies. */
    logout(reason) {
        const redirect = encodeURIComponent(window.location.origin);

        // Clear HttpOnly cookies via proxy
        try {
            this.#fetch(`/oauth/logout?post_logout_redirect_uri=${redirect}`, {
                method: 'GET',
            }).catch(() => {});
        } catch { /* ignore */ }

        // Clear server-side SSO cookie directly
        try {
            const img = new Image();
            img.src = this.#authServer + '/oauth/logout?post_logout_redirect_uri=' + redirect;
        } catch { /* ignore */ }

        this.#clearSession();
        if (this.#onAuthChangeCb) this.#onAuthChangeCb(false, reason || null);
    }

    /** @returns {boolean} Whether user has a valid (non-expired) session */
    isAuthenticated() {
        return Boolean(this.#sessionPayload?.exp && this.#sessionPayload.exp * 1000 > Date.now());
    }

    /**
     * Get current user info. Returns a frozen, immutable object.
     * @returns {{ sub: string, email: string, user_id: number, app_id: string, scope: string|null, issuer: string, expires_at: Date, issued_at: Date } | null}
     */
    getUser() {
        const p = this.#sessionPayload;
        if (!p) return null;
        try {
            return Object.freeze({
                sub:        p.sub,
                email:      p.email || p.sub,
                user_id:    p.user_id,
                app_id:     p.app_id,
                scope:      p.scope || null,
                issuer:     p.iss,
                expires_at: new Date(p.exp * 1000),
                issued_at:  new Date(p.iat * 1000),
            });
        } catch { return null; }
    }

    /**
     * Access token is stored in HttpOnly cookies — browser cannot read it.
     * Use the proxy to make authenticated requests to your backend.
     * @returns {null} Always null by design.
     */
    getAccessToken() { return null; }

    /** Refresh the access token using the HttpOnly refresh_token cookie. */
    async refreshAccessToken() {
        try {
            const res = await this.#fetch('/token/refresh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({}),
            });
            if (res.ok) {
                const payload = await this.verifyToken();
                return Boolean(payload);
            }
        } catch (e) {
            console.error('[AuthSDK] Refresh failed:', e.message);
        }
        this.#clearSession();
        return false;
    }

    /** Verify the current access token with the auth server. */
    async verifyToken() {
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
        } catch (e) {
            console.error('[AuthSDK] Verify failed:', e.message);
            this.#sessionPayload = null;
            return null;
        }
    }

    /** Restore session from HttpOnly cookies (call on page load). */
    async restoreSession() {
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
     * Handle OAuth callback — call this on your callback page.
     * Exchanges the authorization code for tokens via the proxy.
     * @returns {Promise<boolean>} true if callback was successfully processed
     */
    async handleCallback() {
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

        // Remove sensitive params from URL bar immediately
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
                    // NOTE: client_secret is NOT here — the proxy injects it server-side
                }),
            });

            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                console.error('[AuthSDK] Token exchange failed:', err.detail || res.status);
                return false;
            }

            const restored = await this.restoreSession();
            if (restored && this.#onAuthChangeCb) this.#onAuthChangeCb(true);
            return restored;
        } catch (e) {
            console.error('[AuthSDK] Token exchange error:', e.message);
            return false;
        }
    }

    /** Register a callback for login/logout events. */
    onAuthChange(callback) { this.#onAuthChangeCb = callback; }

    /** Start auto-refresh and real-time revocation monitoring. */
    startAutoRefresh() {
        this.#startSessionMonitor();
        this.#startSessionStream();
    }

    /** Seconds until the access token expires (0 if expired/missing). */
    getTimeUntilExpiry() {
        if (!this.#sessionPayload?.exp) return 0;
        return Math.max(0, Math.floor((this.#sessionPayload.exp * 1000 - Date.now()) / 1000));
    }


    /* ─── Private: OAuth Flow ────────────────────────────── */

    async #startOAuthFlow(options = {}) {
        const codeVerifier  = AuthClient.#random(64);
        const codeChallenge = await AuthClient.#sha256Base64Url(codeVerifier);
        const state         = AuthClient.#random(16);

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

        window.location.href = this.#authServer + '/oauth/authorize?' + qs;
    }

    #clearSession() {
        this.#sessionPayload = null;
        this.#stopMonitor();
        this.#stopStream();
    }

    #cleanup() {
        sessionStorage.removeItem('_auth_code_verifier');
        sessionStorage.removeItem('_auth_state');
    }


    /* ─── Private: Auto-Refresh Timer ────────────────────── */

    #startSessionMonitor() {
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

    #stopMonitor() {
        if (this.#sessionInterval) { clearInterval(this.#sessionInterval); this.#sessionInterval = null; }
    }


    /* ─── Private: SSE Real-Time Revocation Stream ───────── */

    #startSessionStream() {
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

    #stopStream() {
        if (this.#eventSource) { this.#eventSource.close(); this.#eventSource = null; }
    }


    /* ─── Private: Networking ────────────────────────────── */

    /**
     * ALL requests go through the proxy. No fallback. No direct calls.
     * The proxy is the security boundary — bypassing it leaks tokens.
     */
    #fetch(path, init) {
        const p = String(path || '').startsWith('/') ? path : `/${path}`;
        return fetch(`${this.#proxyPath}${p}`, { credentials: 'include', ...(init || {}) });
    }


    /* ─── Private Static: Crypto ─────────────────────────── */

    static #random(bytes) {
        const arr = new Uint8Array(bytes);
        crypto.getRandomValues(arr);
        let s = ''; for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
        return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    static async #sha256Base64Url(plain) {
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(plain));
        const arr = new Uint8Array(digest);
        let s = ''; for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
        return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
}


/* ═══════════════════════════════════════════════════════════
 *  PART 2: React Integration — AuthProvider + useAuth()
 *
 *  Usage:
 *    // layout.tsx
 *    import { AuthProvider } from '@/lib/auth-sdk';
 *    <AuthProvider>{children}</AuthProvider>
 *
 *    // any component
 *    import { useAuth } from '@/lib/auth-sdk';
 *    const { user, login, logout, isAuthenticated, loading } = useAuth();
 *
 * ═══════════════════════════════════════════════════════════ */

// React imports (tree-shaken if not used)
import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';


const AuthContext = createContext(undefined);

/**
 * AuthProvider — wrap your app to enable authentication.
 *
 * Reads config from environment variables automatically:
 *   NEXT_PUBLIC_AUTH_SERVER    → Auth server URL
 *   NEXT_PUBLIC_CLIENT_ID     → OAuth client ID
 *   NEXT_PUBLIC_REDIRECT_URI  → Callback URL
 *
 * @example
 *   // app/layout.tsx
 *   import { AuthProvider } from '@/lib/auth-sdk';
 *   export default function Layout({ children }) {
 *     return <html><body><AuthProvider>{children}</AuthProvider></body></html>;
 *   }
 */
export function AuthProvider({ children }) {
    const [client, setClient]     = useState(null);
    const [isAuth, setIsAuth]     = useState(false);
    const [user, setUser]         = useState(null);
    const [loading, setLoading]   = useState(true);
    const [reason, setReason]     = useState(null);

    useEffect(() => {
        const init = async () => {
            try {
                const c = new AuthClient({
                    authServer:  process.env.NEXT_PUBLIC_AUTH_SERVER,
                    clientId:    process.env.NEXT_PUBLIC_CLIENT_ID,
                    redirectUri: process.env.NEXT_PUBLIC_REDIRECT_URI,
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

    const login  = useCallback((opts) => client?.login(opts), [client]);
    const logout = useCallback(() => { client?.logout(); setUser(null); setIsAuth(false); setReason(null); }, [client]);

    return React.createElement(AuthContext.Provider, {
        value: { isAuthenticated: isAuth, user, login, logout, loading, logoutReason: reason, authClient: client },
    }, children);
}

/**
 * useAuth() — access auth state in any component.
 *
 * @returns {{ isAuthenticated: boolean, user: object|null, login: Function, logout: Function, loading: boolean, logoutReason: string|null }}
 *
 * @example
 *   const { user, login, logout, isAuthenticated, loading } = useAuth();
 *   if (loading) return <p>Loading...</p>;
 *   if (!isAuthenticated) return <button onClick={login}>Login</button>;
 *   return <p>Hello {user.email}! <button onClick={logout}>Logout</button></p>;
 */
export function useAuth() {
    const ctx = useContext(AuthContext);
    if (ctx === undefined) throw new Error('useAuth() must be inside <AuthProvider>');
    return ctx;
}


/* ═══════════════════════════════════════════════════════════
 *  Exports
 * ═══════════════════════════════════════════════════════════ */

export { AuthClient };
export default AuthClient;
