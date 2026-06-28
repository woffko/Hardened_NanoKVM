import { http } from '@/lib/http.ts';
import { getCsrfToken } from '@/lib/cookie.ts';
import { getBaseUrl } from '@/lib/service.ts';

export type SystemVersion = {
  version: string;
  target: string;
  baseVersion: string;
  kernelVersion: string;
  rootfsVersion: string;
  model: string;
  hardwareVersion: string;
  source: string;
};

export type SystemLatest = {
  kind: string;
  format: number;
  channel: string;
  version: string;
  target: string;
  name: string;
  sha256: string;
  sha512: string;
  size: number;
  url: string;
  releaseNotesUrl: string;
};

export type SystemStagedUpdate = {
  version: string;
  target: string;
  channel: string;
  archiveName: string;
  size: number;
  sha256: string;
  stagedAt: number;
  baseVersion: string;
  kernelVersion: string;
  requiredFreeBytes: number;
  requiresReboot: boolean;
  fileCount: number;
  imageCount: number;
  destructive: boolean;
};

export type SystemPendingUpdate = {
  version: string;
  target: string;
  backupId: string;
  installedAt: number;
  requiresReboot: boolean;
  fileCount: number;
};

export type SystemRollbackInfo = {
  version: string;
  target: string;
  backupId: string;
  installedAt: number;
  fileCount: number;
  requiresReboot: boolean;
};

export type SystemBootHealth = {
  backendRunning: boolean;
  versionMatchesPending: boolean;
  bootMarkerPresent: boolean;
  webRootPresent: boolean;
  healthy: boolean;
};

// get application version
export function getVersion() {
  return http.get('/api/application/version');
}

// get current base-system version
export function getSystemVersion() {
  return http.get('/api/system-update/version');
}

// check for base-system updates
export function checkSystemUpdate() {
  return http.get('/api/system-update/check');
}

// get staged base-system update status
export function getSystemUpdateStatus() {
  return http.get('/api/system-update/status');
}

// download and verify a base-system update into staging
export function downloadSystemUpdate() {
  return http.request({
    method: 'post',
    url: '/api/system-update/download',
    timeout: 15 * 60 * 1000
  });
}

// install a staged base-system update
export function installSystemUpdate() {
  return http.request({
    method: 'post',
    url: '/api/system-update/install',
    timeout: 30 * 60 * 1000
  });
}

// rollback the latest base-system update backup
export function rollbackSystemUpdate() {
  return http.post('/api/system-update/rollback');
}

// confirm a pending base-system update as boot-good
export function confirmSystemUpdate() {
  return http.post('/api/system-update/confirm');
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
