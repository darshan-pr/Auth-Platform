'use client';

import { Suspense, useEffect } from 'react';
import { useAuth } from '@/lib/auth-context';
import { useRouter, useSearchParams } from 'next/navigation';

function LoginContent() {
  const { isAuthenticated, login, loading } = useAuth();
  const router = useRouter();
  const searchParams = useSearchParams();
  const revokedByAdmin = searchParams.get('reason') === 'revoked';

  useEffect(() => {
    if (!loading && isAuthenticated) {
      router.replace('/home');
    }
  }, [isAuthenticated, loading, router]);

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

  // If authenticated, don't render anything while redirecting
  if (isAuthenticated) {
    return null;
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="max-w-md w-full space-y-8 p-10 bg-white rounded-xl shadow-2xl">
        {/* Admin revocation notice */}
        {revokedByAdmin && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-center">
            <div className="flex items-center justify-center space-x-2 mb-1">
              <svg className="h-5 w-5 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
              </svg>
              <p className="text-sm font-semibold text-red-800">Session Revoked</p>
            </div>
            <p className="text-xs text-red-600">
              Your session was ended by an administrator. Please sign in again.
            </p>
          </div>
        )}

        <div className="text-center">
          <div className="mx-auto h-16 w-16 bg-indigo-600 rounded-full flex items-center justify-center">
            <svg
              className="h-10 w-10 text-white"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
              />
            </svg>
          </div>
          <h2 className="mt-6 text-3xl font-extrabold text-gray-900">
            Welcome Back
          </h2>
          <p className="mt-2 text-sm text-gray-600">
            Sign in to access your account
          </p>
        </div>

        {/* OAuth SSO info note */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="flex items-start space-x-3">
            <svg className="h-5 w-5 text-blue-600 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
              <p className="text-sm font-medium text-blue-800">
                This app uses OAuth for secure authentication
              </p>
              <p className="text-xs text-blue-600 mt-1">
                You&apos;ll be redirected to the Auth Platform to sign in. If you already 
                have an active session there, you&apos;ll be authorized automatically.
              </p>
            </div>
          </div>
        </div>

        <div className="mt-4 space-y-4">
          <button
            onClick={login}
            className="w-full flex items-center justify-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-sm font-semibold text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-all duration-200 hover:shadow-md"
          >
            <svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" />
            </svg>
            Continue with Auth Platform
          </button>

          <div className="text-center">
            <p className="text-xs text-gray-500">
              Secure authentication powered by OAuth 2.0 with PKCE
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen flex items-center justify-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900 mx-auto" />
        </div>
      }
    >
      <LoginContent />
    </Suspense>
  );
}
