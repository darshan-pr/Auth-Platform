/**
 * Authentication Configuration
 * 
 * Update these values with your auth server details:
 * 1. Get CLIENT_ID from your Auth Platform Admin Console
 * 2. Set AUTH_SERVER to your auth platform URL
 * 3. Set REDIRECT_URI to match your app's callback URL
 */

function cleanEnv(value) {
  if (!value) return '';
  return String(value).trim().replace(/^['"]|['"]$/g, '');
}

export const AUTH_CONFIG = {
  // Your auth server URL (e.g., https://auth.yourplatform.com)
  AUTH_SERVER: cleanEnv(process.env.NEXT_PUBLIC_AUTH_SERVER),
  
  // Your OAuth client ID from the admin console
  CLIENT_ID: cleanEnv(process.env.NEXT_PUBLIC_CLIENT_ID),
  
  // Callback URL - must match what's registered in admin console
  REDIRECT_URI: cleanEnv(process.env.NEXT_PUBLIC_REDIRECT_URI),

  // Optional same-origin proxy for token API calls (helps with tunnel/CORS issues)
  AUTH_PROXY_PATH: cleanEnv(process.env.NEXT_PUBLIC_AUTH_PROXY_PATH) || '/api/auth-proxy',
};
