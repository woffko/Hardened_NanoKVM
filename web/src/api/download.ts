import { http } from '@/lib/http.ts';

// Download image
export function downloadImage(file?: string, sha256sum?: string) {
  const data = {
    file: file ?? '',
    sha256sum: sha256sum ?? ''
  };
  return http.post('/api/download/image', data);
}

export function statusImage() {
  return http.get('/api/download/image/status');
}

export function imageEnabled() {
  return http.get('/api/download/image/enabled');
}

export function getRemoteImageDownloadEnabled() {
  return http.get('/api/download/image/remote/enabled');
}

export function setRemoteImageDownloadEnabled(enabled: boolean) {
  return http.post('/api/download/image/remote/enabled', { enabled });
}
