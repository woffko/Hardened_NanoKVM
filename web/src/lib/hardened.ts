export const HARDENED_NAME = 'Hardened NanoKVM';
export const HARDENED_SHORT_NAME = 'Hardened';
export const HARDENED_VERSION = 'alfa - 0.1.8';
export const HARDENED_LOGO_SRC = '/hardened-logo.png';

export function formatHardenedVersion(version?: string) {
  const value = version?.trim();
  if (!value) return HARDENED_VERSION;
  if (value.toLowerCase().startsWith('alfa')) return value;
  return `alfa - ${value}`;
}
