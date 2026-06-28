import { http } from '@/lib/http';

export function login(username: string, password: string) {
  const data = {
    username,
    password
  };
  return http.post('/api/auth/login', data);
}

export function getSetupState() {
  return http.get('/api/auth/setup');
}

export function setupFirstAccount(username: string, password: string) {
  const data = {
    username,
    password
  };
  return http.post('/api/auth/setup', data);
}

export function logout() {
  return http.post('/api/auth/logout');
}

export function getAccount() {
  return http.get('/api/auth/account');
}

export function changePassword(username: string, password: string) {
  const data = {
    username,
    password
  };
  return http.post('/api/auth/password', data);
}

export function isPasswordUpdated() {
  return http.get('/api/auth/password');
}
