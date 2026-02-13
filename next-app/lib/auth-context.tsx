'use client';

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

// Type definitions
interface User {
  email: string;
  user_id: string;
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
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [authClient, setAuthClient] = useState<any>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  // Initialize auth client
  useEffect(() => {
    const initAuth = async () => {
      try {
        // Dynamically import the auth modules
        const { AUTH_CONFIG } = await import('@/lib/config');
        const { default: AuthClient } = await import('@/lib/auth-sdk.js');
        
        const client = new AuthClient(AUTH_CONFIG);
        setAuthClient(client);

        // Handle OAuth callback if present
        const handled = await client.handleCallback();
        
        // Check authentication state
        const authenticated = client.isAuthenticated();
        setIsAuthenticated(authenticated);
        
        if (authenticated) {
          setUser(client.getUser());
        }

        // Register auth change callback
        client.onAuthChange((authenticated: boolean) => {
          setIsAuthenticated(authenticated);
          if (authenticated) {
            setUser(client.getUser());
          } else {
            setUser(null);
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
