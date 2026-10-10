import { http } from '@/lib/http.ts';

export type TotpStatus = {
  enabled: boolean;
  /** False until the device clock has been synchronized; enrolment is refused while false. */
  clockSynced: boolean;
  backupCodesRemaining: number;
  enrolledAt: number;
  /** Whether configuration requires a second factor on this device. */
  required: boolean;
};

export type TotpEnrollment = {
  secret: string;
  otpauthUri: string;
};

export type BackupCodes = {
  backupCodes: string[];
};

export function getStatus() {
  return http.get('/api/auth/totp');
}

export function enroll(password: string) {
  return http.post('/api/auth/totp/enroll', { password });
}

export function confirm(code: string) {
  return http.post('/api/auth/totp/confirm', { code });
}

export function disable(password: string) {
  return http.delete('/api/auth/totp', { password });
}

export function regenerateBackupCodes(password: string) {
  return http.post('/api/auth/totp/backup-codes', { password });
}

export function setRequired(required: boolean) {
  return http.post('/api/auth/totp/required', { required });
}

/** Second login step: exchange the pending ticket plus a code for a session. */
export function loginTotp(code: string) {
  return http.post('/api/auth/login/totp', { code });
}
