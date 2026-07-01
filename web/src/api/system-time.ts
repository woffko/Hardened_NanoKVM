import { http } from '@/lib/http.ts';

export type TimeConfig = {
  ntpEnabled: boolean;
  timezone: string;
  servers: string[];
};

export type TimeConfigResponse = {
  config: TimeConfig;
  currentTime: string;
  gateway: string;
  defaultServers: string[];
  timezoneOptions: string[];
};

export function getConfig() {
  return http.get('/api/system/time');
}

export function setConfig(config: TimeConfig) {
  return http.post('/api/system/time', config);
}

export function syncNow() {
  return http.post('/api/system/time/sync');
}
