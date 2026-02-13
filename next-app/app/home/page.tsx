'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@/lib/auth-context';
import { useRouter } from 'next/navigation';

export default function HomePage() {
  const { isAuthenticated, user, logout, loading, authClient } = useAuth();
  const router = useRouter();
  const [timeUntilExpiry, setTimeUntilExpiry] = useState<number | null>(null);

  useEffect(() => {
    if (!loading && !isAuthenticated) {
      router.push('/');
    }
  }, [isAuthenticated, loading, router]);

  useEffect(() => {
    if (authClient) {
      // Immediately set the current time
      setTimeUntilExpiry(authClient.getTimeUntilExpiry());
      
      // Update time until expiry every second
      const interval = setInterval(() => {
        setTimeUntilExpiry(authClient.getTimeUntilExpiry());
      }, 1000);

      return () => clearInterval(interval);
    }
  }, [authClient]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated || !user) {
    return null;
  }

  const formatTime = (seconds: number) => {
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${minutes}m ${secs}s`;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      {/* Session Expiry Warning */}
      {timeUntilExpiry !== null && timeUntilExpiry === 0 && (
        <div className="bg-red-600 text-white px-4 py-3 text-center">
          <div className="flex items-center justify-center space-x-2">
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
            </svg>
            <p className="font-medium">Your session has expired. Please sign in again.</p>
          </div>
        </div>
      )}
      {timeUntilExpiry !== null && timeUntilExpiry > 0 && timeUntilExpiry < 300 && (
        <div className="bg-orange-500 text-white px-4 py-3 text-center">
          <div className="flex items-center justify-center space-x-2">
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
            </svg>
            <p className="font-medium">Your session expires in {formatTime(timeUntilExpiry)}. Please save your work.</p>
          </div>
        </div>
      )}

      {/* Header */}
      <header className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex justify-between items-center">
            <div className="flex items-center space-x-3">
              <div className="h-10 w-10 bg-indigo-600 rounded-full flex items-center justify-center">
                <span className="text-white font-bold text-lg">
                  {user.email.charAt(0).toUpperCase()}
                </span>
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">Dashboard</h1>
                <p className="text-sm text-gray-500">Welcome back!</p>
              </div>
            </div>
            <button
              onClick={logout}
              className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors font-medium"
            >
              Sign Out
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* User Info Card */}
          <div className="bg-white rounded-xl shadow-lg p-6">
            <div className="flex items-center space-x-2 mb-4">
              <svg
                className="h-6 w-6 text-indigo-600"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"
                />
              </svg>
              <h2 className="text-xl font-bold text-gray-900">Profile</h2>
            </div>
            <div className="space-y-3">
              <div>
                <label className="text-sm font-medium text-gray-500">Email</label>
                <p className="text-gray-900 font-medium">{user.email}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-500">User ID</label>
                <p className="text-gray-900 font-mono text-sm">{user.user_id}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-500">App ID</label>
                <p className="text-gray-900 font-mono text-sm">{user.app_id}</p>
              </div>
            </div>
          </div>

          {/* Session Info Card */}
          <div className="bg-white rounded-xl shadow-lg p-6">
            <div className="flex items-center space-x-2 mb-4">
              <svg
                className="h-6 w-6 text-green-600"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
              <h2 className="text-xl font-bold text-gray-900">Session</h2>
            </div>
            <div className="space-y-3">
              <div>
                <label className="text-sm font-medium text-gray-500">Status</label>
                <div className="flex items-center space-x-2">
                  {timeUntilExpiry === null ? (
                    <>
                      <div className="h-2 w-2 bg-gray-400 rounded-full animate-pulse"></div>
                      <p className="text-gray-500 font-medium">Loading...</p>
                    </>
                  ) : (
                    <>
                      <div className={`h-2 w-2 rounded-full ${timeUntilExpiry === 0 ? 'bg-red-500' : timeUntilExpiry < 300 ? 'bg-orange-500 animate-pulse' : 'bg-green-500 animate-pulse'}`}></div>
                      <p className={`font-medium ${timeUntilExpiry === 0 ? 'text-red-600' : timeUntilExpiry < 300 ? 'text-orange-600' : 'text-green-600'}`}>
                        {timeUntilExpiry === 0 ? 'Expired' : timeUntilExpiry < 300 ? 'Expiring Soon' : 'Active'}
                      </p>
                    </>
                  )}
                </div>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-500">Issued At</label>
                <p className="text-gray-900">
                  {new Date(user.issued_at).toLocaleString()}
                </p>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-500">Expires At</label>
                <p className="text-gray-900">
                  {new Date(user.expires_at).toLocaleString()}
                </p>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-500">Time Until Expiry</label>
                <p className="text-gray-900 font-mono">
                  {timeUntilExpiry === null ? 'Loading...' : formatTime(timeUntilExpiry)}
                </p>
                {timeUntilExpiry !== null && timeUntilExpiry < 300 && timeUntilExpiry > 0 && (
                  <p className="text-sm text-orange-600 mt-1">
                    Session expires soon - you'll need to login again
                  </p>
                )}
                {timeUntilExpiry !== null && timeUntilExpiry === 0 && (
                  <p className="text-sm text-red-600 mt-1">
                    Session expired - please login again
                  </p>
                )}
              </div>
            </div>
          </div>

          {/* Features Card */}
          <div className="bg-white rounded-xl shadow-lg p-6 md:col-span-2">
            <div className="flex items-center space-x-2 mb-4">
              <svg
                className="h-6 w-6 text-purple-600"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z"
                />
              </svg>
              <h2 className="text-xl font-bold text-gray-900">Authentication Features</h2>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="border border-gray-200 rounded-lg p-4">
                <div className="text-indigo-600 mb-2">
                  <svg className="h-8 w-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  </svg>
                </div>
                <h3 className="font-semibold text-gray-900 mb-1">OAuth 2.0 with PKCE</h3>
                <p className="text-sm text-gray-600">Secure authorization code flow with proof key</p>
              </div>
              <div className="border border-gray-200 rounded-lg p-4">
                <div className="text-green-600 mb-2">
                  <svg className="h-8 w-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                </div>
                <h3 className="font-semibold text-gray-900 mb-1">Manual Re-authentication</h3>
                <p className="text-sm text-gray-600">Clean session management with manual login after expiry</p>
              </div>
              <div className="border border-gray-200 rounded-lg p-4">
                <div className="text-purple-600 mb-2">
                  <svg className="h-8 w-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <h3 className="font-semibold text-gray-900 mb-1">JWT Tokens</h3>
                <p className="text-sm text-gray-600">Stateless authentication with JSON Web Tokens</p>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
