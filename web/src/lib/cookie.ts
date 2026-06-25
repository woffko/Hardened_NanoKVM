import Cookies from 'js-cookie';

const COOKIE_TOKEN_KEY = 'nano-kvm-token';
const COOKIE_CSRF_KEY = 'nano-kvm-csrf';

export function existToken() {
  const token = Cookies.get(COOKIE_TOKEN_KEY);
  return !!token;
}

export function getToken() {
  const token = Cookies.get(COOKIE_TOKEN_KEY);
  if (!token) return null;

  return token;
}

export function setToken(token: string) {
  Cookies.set(COOKIE_TOKEN_KEY, token, { expires: 30 });
}

export function getCsrfToken() {
  const token = Cookies.get(COOKIE_CSRF_KEY);
  if (!token) return null;

  return token;
}

export function setCsrfToken(token: string) {
  Cookies.set(COOKIE_CSRF_KEY, token, { expires: 30 });
}

export function removeToken() {
  Cookies.remove(COOKIE_TOKEN_KEY);
  Cookies.remove(COOKIE_CSRF_KEY);
}
