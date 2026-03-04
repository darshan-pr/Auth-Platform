/**
 * ============================================================
 *  Auth Platform — JavaScript SDK  (v2.0.0)
 * ============================================================
 *
 *  Drop-in authentication for any web app.
 *  Uses OAuth 2.0 Authorization Code Flow with PKCE.
 *  Zero dependencies. Works with any framework.
 *
 *  Quick start:
 *  ─────────────────────────────────────────────────
 *  1. Set environment variables (or use a .env file):
 *
 *       AUTH_SERVER_URL=https://auth.yourplatform.com
 *       AUTH_CLIENT_ID=your-client-id
 *       AUTH_REDIRECT_URI=https://yourapp.com/callback
 *
 *  2. Initialise the SDK:
 *
 *       const auth = new AuthClient({
 *         // Read from your environment / config — never hardcode in production
 *         AUTH_SERVER:   process.env.AUTH_SERVER_URL,   // or import.meta.env.VITE_AUTH_SERVER
 *         CLIENT_ID:     process.env.AUTH_CLIENT_ID,    // from Admin Console
 *         REDIRECT_URI:  process.env.AUTH_REDIRECT_URI, // must match Admin Console
 *       });
 *
 *  3. Handle the callback & check session:
 *
 *       await auth.handleCallback();
 *       if (auth.isAuthenticated()) {
 *         console.log('Hello', auth.getUser().email);
 *         auth.startAutoRefresh();  // auto token refresh + real-time revocation
 *       } else {
 *         auth.login();
 *       }
 *
 *  That's it. No secrets needed on the frontend.
 *
 *  Environment variable naming by framework:
 *  ──────────────────────────────────────────
 *    Next.js  →  NEXT_PUBLIC_AUTH_SERVER, NEXT_PUBLIC_CLIENT_ID, NEXT_PUBLIC_REDIRECT_URI
 *    Vite     →  VITE_AUTH_SERVER,        VITE_CLIENT_ID,        VITE_REDIRECT_URI
 *    CRA      →  REACT_APP_AUTH_SERVER,   REACT_APP_CLIENT_ID,   REACT_APP_REDIRECT_URI
 *    Plain JS →  pass values directly from your build config or <meta> tags
 *
 * ============================================================
 */

class AuthClient {

    /* ──────────────────────────────────────────────
     *  TRUE PRIVATE STATE
     *  Using # private fields — inaccessible outside this class.
     *  Developers cannot read or mutate tokens, streams, etc.
     * ────────────────────────────────────────────── */
    #authServer;
    #clientId;
    #redirectUri;
    #tokens = null;
    #onAuthChangeCb = null;
    #sessionInterval = null;
    #eventSource = null;

    /**
     * Create an AuthClient instance.
     *
     * @param {Object} config
     * @param {string} config.AUTH_SERVER   - Auth platform URL (from env)
     * @param {string} config.CLIENT_ID    - OAuth Client ID (from Admin Console)
     * @param {string} config.REDIRECT_URI - Callback URL (must match Admin Console)
     */
    constructor(config = {}) {
        if (!config.AUTH_SERVER) {
            throw new Error(
                '[AuthClient] AUTH_SERVER is required.\n' +
                'Set it via environment variable (e.g. NEXT_PUBLIC_AUTH_SERVER).'
            );
        }
        this.#authServer  = config.AUTH_SERVER.replace(/\/+$/, '');
        this.#clientId    = config.CLIENT_ID || '';
        this.#redirectUri = config.REDIRECT_URI || '';

        // Restore any existing session from storage
        this.#loadSession();
    }


    /* =====================================================
     *  PUBLIC API — These are the ONLY methods developers
     *  should use. Everything else is truly private.
     * ===================================================== */

    /**
     * Redirect to the hosted login page (OAuth 2.0 + PKCE).
     * Like "Sign in with Google" — your app never sees the password.
     */
    login() {
        if (!this.#clientId) {
            throw new Error(
                '[AuthClient] CLIENT_ID is not configured.\n' +
                'Get one from the Admin Console and set it via environment variable.'
            );
        }
        this.#startOAuthFlow();
    }

    /**
     * Clear session and notify listeners.
     * @param {string} [reason] - Optional reason: 'revoked_by_admin' | 'session_expired' | null
     */
    logout(reason) {
        this.#clearSession();
        if (this.#onAuthChangeCb) this.#onAuthChangeCb(false, reason || null);
    }

    /**
     * Check if the user has a valid (non-expired) access token.
     * @returns {boolean}
     */
    isAuthenticated() {
        if (!this.#tokens?.access_token) return false;
        try {
            const payload = AuthClient.#decodeJWT(this.#tokens.access_token);
            return payload.exp * 1000 > Date.now();
        } catch {
            return false;
        }
    }

    /**
     * Get current user info decoded from the JWT.
     * Returns a frozen object — cannot be accidentally mutated.
     * @returns {{ email: string, user_id: number, app_id: string, issuer: string, expires_at: Date, issued_at: Date } | null}
     */
    getUser() {
        if (!this.#tokens?.access_token) return null;
        try {
            const p = AuthClient.#decodeJWT(this.#tokens.access_token);
            return Object.freeze({
                email:      p.sub,
                user_id:    p.user_id,
                app_id:     p.app_id,
                issuer:     p.iss,
                expires_at: new Date(p.exp * 1000),
                issued_at:  new Date(p.iat * 1000),
            });
        } catch {
            return null;
        }
    }

    /**
     * Get the raw access token string for Authorization headers.
     * Usage: fetch(url, { headers: { Authorization: `Bearer ${auth.getAccessToken()}` } })
     * @returns {string | null}
     */
    getAccessToken() {
        return this.#tokens?.access_token || null;
    }

    /**
     * Manually refresh the access token using the stored refresh token.
     * Normally you don't need this — startAutoRefresh() handles it automatically.
     * @returns {Promise<boolean>} true if refresh succeeded
     */
    async refreshAccessToken() {
        if (!this.#tokens?.refresh_token) return false;
        try {
            const res = await fetch(this.#authServer + '/token/refresh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ refresh_token: this.#tokens.refresh_token }),
            });
            if (res.ok) {
                const data = await res.json();
                this.#tokens.access_token = data.access_token;
                this.#saveSession();
                return true;
            }
        } catch (err) {
            console.error('[AuthClient] Token refresh failed:', err.message);
        }
        return false;
    }

    /**
     * Verify the current access token with the auth server.
     * @returns {Promise<Object | null>} decoded payload or null
     */
    async verifyToken() {
        if (!this.#tokens?.access_token) return null;
        try {
            const res = await fetch(this.#authServer + '/token/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: this.#tokens.access_token }),
            });
            return await res.json();
        } catch (err) {
            console.error('[AuthClient] Token verify failed:', err.message);
            return null;
        }
    }

    /**
     * Register a callback that fires on login/logout events.
     *
     * @param {(isAuthenticated: boolean, reason?: string) => void} callback
     *
     * The reason parameter on logout:
     *   'revoked_by_admin' — admin force-logged out the user
     *   'session_expired'  — tokens expired and refresh failed
     *   null               — user logged out voluntarily
     *
     * Example:
     *   auth.onAuthChange((loggedIn, reason) => {
     *     if (!loggedIn && reason === 'revoked_by_admin') {
     *       showBanner('Your session was ended by an administrator');
     *     }
     *   });
     */
    onAuthChange(callback) {
        this.#onAuthChangeCb = callback;
    }

    /**
     * Handle the OAuth redirect callback.
     * Call this once on page load (or on your callback route).
     * Returns true if a callback was successfully processed.
     * @returns {Promise<boolean>}
     */
    async handleCallback() {
        const params = new URLSearchParams(window.location.search);
        const code  = params.get('code');
        const state = params.get('state');
        if (!code || !state) return false;

        // CSRF protection
        const savedState = sessionStorage.getItem('_auth_state');
        if (state !== savedState) {
            console.error('[AuthClient] State mismatch — possible CSRF attack');
            this.#cleanupOAuthParams();
            return false;
        }

        const codeVerifier = sessionStorage.getItem('_auth_code_verifier');
        if (!codeVerifier) {
            console.error('[AuthClient] Missing PKCE code_verifier');
            this.#cleanupOAuthParams();
            return false;
        }

        // Remove OAuth params from the URL bar
        window.history.replaceState({}, document.title, window.location.pathname);
        this.#cleanupOAuthParams();

        // Exchange authorization code for tokens
        try {
            const res = await fetch(this.#authServer + '/oauth/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    grant_type:    'authorization_code',
                    code,
                    client_id:     this.#clientId,
                    redirect_uri:  this.#redirectUri,
                    code_verifier: codeVerifier,
                }),
            });

            const data = await res.json();
            if (!res.ok) {
                console.error('[AuthClient] Token exchange failed:', data.detail);
                return false;
            }

            this.#tokens = {
                access_token:  data.access_token,
                refresh_token: data.refresh_token,
            };
            this.#saveSession();
            this.#startSessionMonitor();
            this.#startSessionStream();
            if (this.#onAuthChangeCb) this.#onAuthChangeCb(true);
            return true;
        } catch (err) {
            console.error('[AuthClient] Token exchange error:', err.message);
            return false;
        }
    }

    /**
     * Enable automatic session management:
     *   1. Refreshes the access token before it expires (timer-based)
     *   2. Opens an SSE stream for real-time admin revocation detection
     *
     * Call this AFTER confirming isAuthenticated() === true.
     */
    startAutoRefresh() {
        this.#startSessionMonitor();
        this.#startSessionStream();
    }

    /**
     * Seconds until the access token expires (0 if expired or missing).
     * @returns {number}
     */
    getTimeUntilExpiry() {
        if (!this.#tokens?.access_token) return 0;
        try {
            const p = AuthClient.#decodeJWT(this.#tokens.access_token);
            return Math.max(0, Math.floor((p.exp * 1000 - Date.now()) / 1000));
        } catch {
            return 0;
        }
    }


    /* =====================================================
     *  PRIVATE — OAuth Flow
     * ===================================================== */

    async #startOAuthFlow() {
        const codeVerifier  = AuthClient.#generateRandom(32);
        const codeChallenge = await AuthClient.#sha256Base64Url(codeVerifier);
        const state         = AuthClient.#generateRandom(16);

        sessionStorage.setItem('_auth_code_verifier', codeVerifier);
        sessionStorage.setItem('_auth_state', state);

        const qs = new URLSearchParams({
            client_id:             this.#clientId,
            redirect_uri:          this.#redirectUri,
            response_type:         'code',
            state,
            code_challenge:        codeChallenge,
            code_challenge_method: 'S256',
        });

        window.location.href = this.#authServer + '/oauth/authorize?' + qs;
    }


    /* =====================================================
     *  PRIVATE — Session Storage
     * ===================================================== */

    #loadSession() {
        try {
            const raw = sessionStorage.getItem('_auth_tokens');
            if (raw) this.#tokens = JSON.parse(raw);
        } catch { /* corrupted — ignore */ }
    }

    #saveSession() {
        sessionStorage.setItem('_auth_tokens', JSON.stringify(this.#tokens));
    }

    #clearSession() {
        this.#tokens = null;
        sessionStorage.removeItem('_auth_tokens');
        this.#stopSessionMonitor();
        this.#stopSessionStream();
    }

    #cleanupOAuthParams() {
        sessionStorage.removeItem('_auth_code_verifier');
        sessionStorage.removeItem('_auth_state');
    }


    /* =====================================================
     *  PRIVATE — Token Auto-Refresh Timer
     * ===================================================== */

    #startSessionMonitor() {
        this.#stopSessionMonitor();
        this.#sessionInterval = setInterval(async () => {
            const ttl = this.getTimeUntilExpiry();
            if (ttl <= 0) {
                const ok = await this.refreshAccessToken();
                if (!ok) this.logout('session_expired');
            } else if (ttl < 120) {
                await this.refreshAccessToken();
            }
        }, 15_000);
    }

    #stopSessionMonitor() {
        if (this.#sessionInterval) {
            clearInterval(this.#sessionInterval);
            this.#sessionInterval = null;
        }
    }


    /* =====================================================
     *  PRIVATE — SSE Real-Time Revocation Stream
     *  The server pushes a "revoked" event the instant an
     *  admin force-logouts the user. Zero polling overhead.
     * ===================================================== */

    #startSessionStream() {
        this.#stopSessionStream();
        if (!this.#tokens?.access_token) return;
        if (typeof EventSource === 'undefined') return;

        const url = this.#authServer + '/token/session-stream?token=' + encodeURIComponent(this.#tokens.access_token);
        this.#eventSource = new EventSource(url);

        this.#eventSource.addEventListener('revoked', () => {
            this.#stopSessionStream();
            this.logout('revoked_by_admin');
        });

        this.#eventSource.onerror = async () => {
            if (this.#eventSource?.readyState === EventSource.CLOSED) {
                this.#stopSessionStream();
                const ok = await this.refreshAccessToken();
                if (ok) setTimeout(() => this.#startSessionStream(), 2000);
                else    this.logout('session_expired');
            }
            // CONNECTING state = auto-reconnect, let it be
        };
    }

    #stopSessionStream() {
        if (this.#eventSource) {
            this.#eventSource.close();
            this.#eventSource = null;
        }
    }


    /* =====================================================
     *  PRIVATE STATIC — Crypto & JWT Utilities
     * ===================================================== */

    static #generateRandom(bytes) {
        const arr = new Uint8Array(bytes);
        crypto.getRandomValues(arr);
        return AuthClient.#base64Url(arr);
    }

    static async #sha256Base64Url(plain) {
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(plain));
        return AuthClient.#base64Url(new Uint8Array(digest));
    }

    static #base64Url(buf) {
        let s = '';
        for (let i = 0; i < buf.length; i++) s += String.fromCharCode(buf[i]);
        return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    static #decodeJWT(token) {
        const seg = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
        const json = decodeURIComponent(
            atob(seg).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join('')
        );
        return JSON.parse(json);
    }
}


/* =====================================================
 *  Export for ES modules (Next.js / Vite / etc.)

 * ===================================================== */
export default AuthClient;
