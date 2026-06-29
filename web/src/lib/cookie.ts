import Cookies from 'js-cookie';

const COOKIE_TOKEN_KEY = 'nano-kvm-token';
const COOKIE_CSRF_KEY = 'nano-kvm-csrf';

function cookieExpires(expiresAt?: number) {
  if (expiresAt && expiresAt > Date.now() / 1000) {
    return new Date(expiresAt * 1000);
  }

  return 30;
}

export function existToken() {
  return !!getCsrfToken();
}

export function getCsrfToken() {
  const token = Cookies.get(COOKIE_CSRF_KEY);
  if (!token) return null;

  return token;
}

export function setCsrfToken(token: string, expiresAt?: number) {
  Cookies.set(COOKIE_CSRF_KEY, token, { expires: cookieExpires(expiresAt) });
}

export function removeToken() {
  // Removes the old JS-readable token cookie from pre-hardening builds.
  // Current sessions are cleared by /api/auth/logout via an HttpOnly cookie.
  Cookies.remove(COOKIE_TOKEN_KEY);
  Cookies.remove(COOKIE_CSRF_KEY);
}
