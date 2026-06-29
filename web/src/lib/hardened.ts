export const HARDENED_NAME = 'Hardened NanoKVM';
export const HARDENED_SHORT_NAME = 'Hardened';
export const HARDENED_VERSION = 'beta 2.0.1';
export const HARDENED_LOGO_SRC = '/hardened-logo.png';

export function formatHardenedVersion(version?: string) {
  const value = version?.trim();
  if (!value) return HARDENED_VERSION;
  const lower = value.toLowerCase();
  if (lower.startsWith('alfa') || lower.startsWith('alpha') || lower.startsWith('beta')) {
    return value;
  }
  if (value.startsWith('2.0.')) {
    return `beta ${value}`;
  }
  return `beta - ${value}`;
}
