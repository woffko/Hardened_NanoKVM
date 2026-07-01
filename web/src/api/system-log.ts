import { http } from '@/lib/http.ts';

export type SystemLogConfig = {
  remoteEnabled: boolean;
  remoteHost: string;
  remotePort: number;
  priority: number;
  bufferKb: number;
  rotations: number;
  smallOutput: boolean;
  stripTimestamps: boolean;
  kernelEnabled: boolean;
  kernelConsoleLevel: number;
};

export type SystemLogKind = 'system' | 'kernel' | 'backend';

export function getConfig() {
  return http.get('/api/system-log/config');
}

export function setConfig(config: SystemLogConfig) {
  return http.post('/api/system-log/config', config);
}

export function getMessages(kind: SystemLogKind, lines: number) {
  return http.get('/api/system-log/messages', {
    params: { kind, lines }
  });
}

export function sendTestMessage() {
  return http.post('/api/system-log/test');
}
