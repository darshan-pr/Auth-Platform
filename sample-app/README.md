# Notes App — Auth Platform Integration Example

A simple Notes application that demonstrates how to integrate the **Auth Platform** into any frontend project using OAuth 2.0 Authorization Code Flow with PKCE.

This is exactly how you'd integrate any external auth provider (Google, GitHub, etc.) — but using our own Auth Platform.

---

## Architecture

```
config.js   → Configuration (AUTH_SERVER URL, CLIENT_ID)
auth.js     → Reusable Auth SDK (AuthClient class) — drop into any project
app.js      → Your app logic (Notes CRUD) — no auth concerns here
index.html  → UI with landing page + app page
style.css   → Styles
```

**Key Principle**: `auth.js` knows nothing about notes. `app.js` knows nothing about OAuth. They communicate through a clean API.

---

## Quick Start

### 1. Start the Auth Platform backend

```bash
cd backend
uvicorn app.main:app --reload --port 8000
```

### 2. Register your app in the Admin Console

Open [http://localhost:3000](http://localhost:3000) (Admin Console) and create a new app:

- **App Name**: Notes App (or anything)
- **Redirect URI**: `http://localhost:3001/index.html`

You'll get a **Client ID** (app_id). Copy it.

### 3. Configure the sample app

Open `config.js` and paste your Client ID:

```javascript
const AUTH_CONFIG = {
    AUTH_SERVER: 'http://localhost:8000',
    CLIENT_ID: 'your-client-id-here',    // ← paste here
    REDIRECT_URI: window.location.origin + window.location.pathname,
};
```

### 4. Serve the sample app

```bash
cd sample-app
python3 -m http.server 3001
```

### 5. Open the app

Go to [http://localhost:3001](http://localhost:3001) → Click **"Sign in with Auth Platform"** → Sign up or log in → You're in!

---

## How the Auth Flow Works

```
Your App                          Auth Platform
───────                           ─────────────
1. User clicks "Sign in"
       │
       ├── Generate PKCE pair ──►
       │   (code_verifier +
       │    code_challenge)
       │
       ├── Redirect to ─────────► /oauth/authorize
       │                           Shows login page
       │                           User enters credentials
       │                           ◄── Redirects back with
       │                               ?code=xxx&state=yyy
       │
2. App receives callback
       │
       ├── Exchange code ────────► /oauth/token
       │   (code + code_verifier)  Verifies PKCE
       │                           ◄── Returns tokens
       │                               { access_token,
       │                                 refresh_token }
       │
3. App stores tokens in
   sessionStorage
       │
4. App shows protected content
       │
5. Before token expires ─────────► /token/refresh
                                    ◄── New access_token
```

No client secret is ever sent from the frontend. PKCE ensures security.

---

## AuthClient API Reference

### Initialization

```javascript
const auth = new AuthClient(AUTH_CONFIG);
```

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `auth.login()` | `void` | Redirects to Auth Platform login page |
| `auth.logout()` | `void` | Clears session, triggers auth change callback |
| `auth.isAuthenticated()` | `boolean` | True if access token exists and isn't expired |
| `auth.getUser()` | `object \| null` | Decoded user info: `{ email, user_id, app_id, expires_at }` |
| `auth.getAccessToken()` | `string \| null` | Raw JWT for `Authorization: Bearer` headers |
| `auth.refreshAccessToken()` | `Promise<boolean>` | Refreshes the access token using refresh token |
| `auth.verifyToken()` | `Promise<object>` | Calls `/token/verify` to server-side validate the token |
| `auth.handleCallback()` | `Promise<boolean>` | Processes the OAuth callback (code exchange). Call on page load. |
| `auth.onAuthChange(callback)` | `void` | Register a callback for auth state changes |
| `auth.startAutoRefresh()` | `void` | Starts background timer that auto-refreshes before expiry |
| `auth.getTimeUntilExpiry()` | `number` | Seconds until access token expires |

### Example: Protecting Content

```javascript
const auth = new AuthClient(AUTH_CONFIG);

// Handle OAuth callback (if redirected back from login)
await auth.handleCallback();

if (auth.isAuthenticated()) {
    // Show protected content
    const user = auth.getUser();
    document.getElementById('welcome').textContent = `Hello, ${user.email}`;
    auth.startAutoRefresh();
} else {
    // Show login button
    document.getElementById('loginBtn').onclick = () => auth.login();
}
```

### Example: Making Authenticated API Calls

```javascript
const token = auth.getAccessToken();

const response = await fetch('https://your-api.com/data', {
    headers: {
        'Authorization': `Bearer ${token}`
    }
});
```

---

## Integrating into Your Own Project

To add Auth Platform authentication to any project, you only need **two files**:

1. **Copy `config.js`** — update `AUTH_SERVER` and `CLIENT_ID`
2. **Copy `auth.js`** — no changes needed, it's a standalone module

Then in your app:

```html
<script src="config.js"></script>
<script src="auth.js"></script>
<script>
    const auth = new AuthClient(AUTH_CONFIG);
    // ... use auth.login(), auth.isAuthenticated(), etc.
</script>
```

That's it. No backend changes to your app. No secrets on the frontend.

---

## File Overview

| File | Purpose |
|------|---------|
| `config.js` | Auth server URL and Client ID — the only file you edit |
| `auth.js` | Reusable Auth SDK — handles OAuth, PKCE, tokens, auto-refresh |
| `app.js` | Notes App logic — CRUD, rendering, localStorage persistence |
| `index.html` | Landing page (login) + App page (notes + sidebar) |
| `style.css` | Clean responsive styles |
| `README.md` | This file |
