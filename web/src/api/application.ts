import { http } from '@/lib/http.ts';
import { getCsrfToken } from '@/lib/cookie.ts';
import { getBaseUrl } from '@/lib/service.ts';

// get application version
export function getVersion() {
  return http.get('/api/application/version');
}

// update application to latest version
export function update() {
  return http.request({
    method: 'post',
    url: '/api/application/update',
    timeout: 15 * 60 * 1000
  });
}

// offline update application
export function offlineUpdate(data: FormData) {
  const baseUrl = getBaseUrl('http');
  const url = `${baseUrl}/api/application/update/offline`;
  const csrfToken = getCsrfToken();
  return fetch(url, {
    method: 'POST',
    headers: csrfToken ? { 'x-csrf-token': csrfToken } : undefined,
    body: data
  });
}

// enable/disable preview updates
export function setPreviewUpdates(enable: boolean) {
  const data = {
    enable
  };
  return http.post('/api/application/preview', data);
}

// get preview updates state
export function getPreviewUpdates() {
  return http.get('/api/application/preview');
}
