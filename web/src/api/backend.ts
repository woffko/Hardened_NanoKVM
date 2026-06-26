import { http } from '@/lib/http.ts';

export function getHealth() {
  return http.get('/api/health');
}
