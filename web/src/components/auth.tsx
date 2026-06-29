import { ReactNode, useEffect, useState } from 'react';
import { Navigate } from 'react-router-dom';

import { existToken, removeToken, setCsrfToken } from '@/lib/cookie.ts';

type AuthState = 'checking' | 'allowed' | 'denied';

export const ProtectedRoute = ({ children }: { children: ReactNode }) => {
  const [authState, setAuthState] = useState<AuthState>(() =>
    existToken() ? 'allowed' : 'checking'
  );

  useEffect(() => {
    if (existToken()) {
      setAuthState('allowed');
      return;
    }

    let cancelled = false;

    async function recoverSession() {
      try {
        const response = await fetch('/api/auth/account', {
          credentials: 'include',
          headers: { Accept: 'application/json' }
        });

        if (!response.ok) {
          throw new Error(`account check failed: ${response.status}`);
        }

        const body = await response.json();
        if (body?.code === 0 && body.data?.csrfToken) {
          setCsrfToken(body.data.csrfToken, body.data.expiresAt);
          if (!cancelled) setAuthState('allowed');
          return;
        }
      } catch (err) {
        console.log(err);
      }

      removeToken();
      if (!cancelled) setAuthState('denied');
    }

    recoverSession();

    return () => {
      cancelled = true;
    };
  }, []);

  if (authState === 'checking') {
    return null;
  }

  if (authState === 'denied') {
    return <Navigate to={'/auth/login'} replace />;
  }

  return children;
};
