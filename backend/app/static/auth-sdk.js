/**
 * ============================================================
 *  Auth Platform — JavaScript SDK
 * ============================================================
 * 
 *  Drop-in authentication module for any frontend app.
 *  Uses OAuth 2.0 Authorization Code Flow with PKCE.
 * 
 *  Usage:
 *    <script src="config.js"></script>
 *    <script src="auth.js"></script>
 *    <script>
 *      const auth = new AuthClient(AUTH_CONFIG);
 *      
 *      // Check if user is logged in
 *      if (auth.isAuthenticated()) {
 *          const user = auth.getUser();
 *          console.log('Hello', user.email);
 *      }
 *      
 *      // Login
 *      auth.login();
 *      
 *      // Logout
 *      auth.logout();
 *    </script>
 * 
 *  That's it. No secrets. No backend needed on your app.
 * ============================================================
 */

class AuthClient {
    constructor(config) {
        this.authServer = config.AUTH_SERVER;
        this.clientId = config.CLIENT_ID;
        this.redirectUri = config.REDIRECT_URI;

        this._tokens = null;
        this._user = null;
        this._onAuthChange = null;
        this._sessionInterval = null;

        // Load tokens from session storage
        this._loadSession();
    }

    // ==================== Public API ====================

    /**
     * Start OAuth login flow — redirects to the auth platform's login page.
     * Like clicking "Sign in with Google".
     */
    login() {
        if (!this.clientId) {
            throw new Error(
                'CLIENT_ID is not configured. Set it in config.js.\n' +
                'Get one from the Admin Console.'
            );
        }
        this._startOAuthFlow();
    }

    /**
     * Clear session and optionally redirect to login
     */
    logout() {
        this._clearSession();
        if (this._onAuthChange) this._onAuthChange(false);
    }

    /**
     * Returns true if user has a valid (non-expired) access token
     */
    isAuthenticated() {
        if (!this._tokens?.access_token) return false;
        try {
            const payload = this._decodeJWT(this._tokens.access_token);
            return payload.exp * 1000 > Date.now();
        } catch {
            return false;
        }
    }

    /**
     * Get the current user info decoded from the JWT
     * Returns { email, user_id, app_id, exp, iss } or null
     */
    getUser() {
        if (!this._tokens?.access_token) return null;
        try {
            const payload = this._decodeJWT(this._tokens.access_token);
            return {
                email: payload.sub,
                user_id: payload.user_id,
                app_id: payload.app_id,
                issuer: payload.iss,
                expires_at: new Date(payload.exp * 1000),
                issued_at: new Date(payload.iat * 1000),
            };
        } catch {
            return null;
        }
    }

    /**
     * Get the raw access token (for Authorization headers)
     */
    getAccessToken() {
        return this._tokens?.access_token || null;
    }

    /**
     * Refresh the access token using the refresh token
     */
    async refreshAccessToken() {
        if (!this._tokens?.refresh_token) return false;

        try {
            const res = await fetch(`${this.authServer}/token/refresh`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ refresh_token: this._tokens.refresh_token }),
            });

            if (res.ok) {
                const data = await res.json();
                this._tokens.access_token = data.access_token;
                this._saveSession();
                return true;
            }
        } catch (err) {
            console.error('[AuthClient] Token refresh failed:', err);
        }
        return false;
    }

    /**
     * Verify the current access token with the server
     */
    async verifyToken() {
        if (!this._tokens?.access_token) return null;

        try {
            const res = await fetch(`${this.authServer}/token/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: this._tokens.access_token }),
            });
            return await res.json();
        } catch (err) {
            console.error('[AuthClient] Token verify failed:', err);
            return null;
        }
    }

    /**
     * Register a callback for auth state changes
     * callback(isAuthenticated: boolean)
     */
    onAuthChange(callback) {
        this._onAuthChange = callback;
    }

    /**
     * Handle the OAuth callback if we're returning from the auth platform.
     * Returns true if a callback was handled, false otherwise.
     * Call this on page load.
     */
    async handleCallback() {
        const params = new URLSearchParams(window.location.search);
        const code = params.get('code');
        const state = params.get('state');

        if (!code || !state) return false;

        // Verify state (CSRF protection)
        const savedState = sessionStorage.getItem('_auth_state');
        if (state !== savedState) {
            console.error('[AuthClient] State mismatch — possible CSRF attack');
            this._cleanupOAuthParams();
            return false;
        }

        // Get PKCE code_verifier
        const codeVerifier = sessionStorage.getItem('_auth_code_verifier');
        if (!codeVerifier) {
            console.error('[AuthClient] Missing PKCE code_verifier');
            this._cleanupOAuthParams();
            return false;
        }

        // Clean URL
        window.history.replaceState({}, document.title, window.location.pathname);
        this._cleanupOAuthParams();

        // Exchange code for tokens
        try {
            const res = await fetch(`${this.authServer}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    grant_type: 'authorization_code',
                    code: code,
                    client_id: this.clientId,
                    redirect_uri: this.redirectUri,
                    code_verifier: codeVerifier,
                }),
            });

            const data = await res.json();

            if (res.ok) {
                this._tokens = {
                    access_token: data.access_token,
                    refresh_token: data.refresh_token,
                };
                this._saveSession();
                this._startSessionMonitor();
                if (this._onAuthChange) this._onAuthChange(true);
                return true;
            } else {
                console.error('[AuthClient] Token exchange failed:', data.detail);
                return false;
            }
        } catch (err) {
            console.error('[AuthClient] Token exchange error:', err);
            return false;
        }
    }

    /**
     * Start automatic session monitoring — auto-refreshes before expiry
     */
    startAutoRefresh() {
        this._startSessionMonitor();
    }

    /**
     * Get seconds until the access token expires
     */
    getTimeUntilExpiry() {
        if (!this._tokens?.access_token) return 0;
        try {
            const payload = this._decodeJWT(this._tokens.access_token);
            return Math.max(0, Math.floor((payload.exp * 1000 - Date.now()) / 1000));
        } catch {
            return 0;
        }
    }

    // ==================== Internal: OAuth Flow ====================

    async _startOAuthFlow() {
        const codeVerifier = this._generateCodeVerifier();
        const codeChallenge = await this._generateCodeChallenge(codeVerifier);
        const state = this._generateState();

        // Store PKCE params for the callback
        sessionStorage.setItem('_auth_code_verifier', codeVerifier);
        sessionStorage.setItem('_auth_state', state);

        const params = new URLSearchParams({
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            response_type: 'code',
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
        });

        window.location.href = `${this.authServer}/oauth/authorize?${params}`;
    }

    // ==================== Internal: Session Management ====================

    _loadSession() {
        try {
            const saved = sessionStorage.getItem('_auth_tokens');
            if (saved) this._tokens = JSON.parse(saved);
        } catch { /* ignore */ }
    }

    _saveSession() {
        sessionStorage.setItem('_auth_tokens', JSON.stringify(this._tokens));
    }

    _clearSession() {
        this._tokens = null;
        this._user = null;
        sessionStorage.removeItem('_auth_tokens');
        this._stopSessionMonitor();
    }

    _cleanupOAuthParams() {
        sessionStorage.removeItem('_auth_code_verifier');
        sessionStorage.removeItem('_auth_state');
    }

    _startSessionMonitor() {
        this._stopSessionMonitor();
        this._sessionInterval = setInterval(async () => {
            const ttl = this.getTimeUntilExpiry();

            if (ttl <= 0) {
                // Expired — try refresh
                const refreshed = await this.refreshAccessToken();
                if (!refreshed) {
                    console.log('[AuthClient] Session expired, refresh failed');
                    this.logout();
                }
            } else if (ttl < 120) {
                // Less than 2 minutes — proactively refresh
                console.log(`[AuthClient] Token expiring in ${ttl}s, refreshing...`);
                await this.refreshAccessToken();
            }
        }, 15000);
    }

    _stopSessionMonitor() {
        if (this._sessionInterval) {
            clearInterval(this._sessionInterval);
            this._sessionInterval = null;
        }
    }

    // ==================== Internal: PKCE Crypto ====================

    _generateCodeVerifier() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return this._base64UrlEncode(array);
    }

    async _generateCodeChallenge(verifier) {
        const data = new TextEncoder().encode(verifier);
        const digest = await crypto.subtle.digest('SHA-256', data);
        return this._base64UrlEncode(new Uint8Array(digest));
    }

    _generateState() {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return this._base64UrlEncode(array);
    }

    _base64UrlEncode(buffer) {
        let str = '';
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < bytes.byteLength; i++) {
            str += String.fromCharCode(bytes[i]);
        }
        return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    // ==================== Internal: JWT ====================

    _decodeJWT(token) {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const json = decodeURIComponent(
            atob(base64).split('').map(c =>
                '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
            ).join('')
        );
        return JSON.parse(json);
    }
}
