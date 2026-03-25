'use client';

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

// Type definitions
interface User {
  email: string;
  user_id: number;
  app_id: string;
  issuer: string;
  expires_at: Date;
  issued_at: Date;
}

interface AuthContextType {
  isAuthenticated: boolean;
  user: User | null;
  login: () => void;
  logout: () => void;
  loading: boolean;
  authClient: any;
  logoutReason: string | null;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [authClient, setAuthClient] = useState<any>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [logoutReason, setLogoutReason] = useState<string | null>(null);

  // Initialize auth client
  useEffect(() => {
    const initAuth = async () => {
      try {
        // Dynamically import the auth modules
        const { AUTH_CONFIG } = await import('@/lib/config');
        const { default: AuthClient } = await import('@/lib/auth-sdk.js');
        
        const client: any = new AuthClient(AUTH_CONFIG);
        setAuthClient(client);

        // Handle OAuth callback if present
        const handled = await client.handleCallback();

        // Cookie-backed restore on normal page loads (no callback params).
        let authenticated = client.isAuthenticated();
        if (!authenticated && !handled) {
          authenticated = await client.restoreSession();
        }
        setIsAuthenticated(authenticated);
        
        if (authenticated) {
          setUser(client.getUser());
          if (!handled) {
            // Start polling the server for session validity.
            // This catches admin-revoked sessions in near real time.
            client.startAutoRefresh();
          }
        }

        // Register auth change callback — receives (isAuth, reason?)
        client.onAuthChange((authenticated: boolean, reason?: string) => {
          setIsAuthenticated(authenticated);
          if (authenticated) {
            setUser(client.getUser());
            setLogoutReason(null);
          } else {
            setUser(null);
            if (reason) {
              setLogoutReason(reason);
            }
          }
        });

        setLoading(false);
      } catch (error) {
        console.error('Failed to initialize auth:', error);
        setLoading(false);
      }
    };

    initAuth();
  }, []);

  const login = useCallback(() => {
    if (authClient) {
      authClient.login();
    }
  }, [authClient]);

  const logout = useCallback(() => {
    if (authClient) {
      authClient.logout();
      setUser(null);
      setIsAuthenticated(false);
      setLogoutReason(null);
    }
  }, [authClient]);

  return (
    <AuthContext.Provider
      value={{
        isAuthenticated,
        user,
        login,
        logout,
        loading,
        authClient,
        logoutReason,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
