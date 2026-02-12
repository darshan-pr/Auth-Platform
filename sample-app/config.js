/**
 * ============================================================
 *  Auth Platform — Client Configuration
 * ============================================================
 * 
 *  SETUP:
 *  1. Go to Admin Console (http://localhost:3000)
 *  2. Create an app → you'll get a CLIENT_ID
 *  3. Set the redirect URI to where this app runs
 *  4. Paste the CLIENT_ID below
 * 
 *  That's it. No secrets needed on the frontend.
 * ============================================================
 */

const AUTH_CONFIG = {
    // Auth Platform server URL
    AUTH_SERVER: 'https://web-production-4d65b.up.railway.app',

    // Your app's Client ID (obtained from Admin Console)
    // Replace this with your actual app_id
    CLIENT_ID: '966d46cc8cee30dd',

    // Where the auth platform redirects after login
    // Must match the redirect_uri registered in Admin Console
    REDIRECT_URI: window.location.origin + window.location.pathname,
};
