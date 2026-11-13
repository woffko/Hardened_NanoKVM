import semver from 'semver';

import type { SystemLatest, SystemStagedUpdate } from '@/api/application.ts';

export type SystemOffer = {
  latest: SystemLatest | null;
  staged: SystemStagedUpdate | null;
  // The backend's own verdict: the release is newer than the running system
  // and nothing it requires is missing.
  updateAvailable: boolean;
  blocked: boolean;
  appUpdateRequired: boolean;
  downloading: boolean;
};

export function stagedMatchesLatest(
  staged: SystemStagedUpdate | null,
  latest: SystemLatest | null
): boolean {
  if (!staged || !latest) return true;

  return (
    staged.version === latest.version &&
    staged.archiveName === latest.name &&
    staged.sha256 === latest.sha256
  );
}

// A download is offered only for a release that the backend called newer than
// the running system and that is newer than what is already staged. Anything
// else the backend refuses, and offering it again after each refusal loops.
export function canOfferSystemDownload(offer: SystemOffer): boolean {
  const { latest, staged } = offer;
  if (!latest || !offer.updateAvailable) return false;
  if (offer.blocked || offer.appUpdateRequired || offer.downloading) return false;
  if (!staged) return true;
  if (stagedMatchesLatest(staged, latest)) return false;
  if (semver.valid(staged.version) && semver.valid(latest.version)) {
    return semver.gt(latest.version, staged.version);
  }
  return true;
}

// The backend's reason for a refusal, from the answer or from a failed request,
// so that the page says why instead of only that it failed.
export function refusalMessage(answer: unknown, fallback: string): string {
  const source = answer as { msg?: unknown; response?: { data?: { msg?: unknown } } } | null;
  const message = source?.response?.data?.msg ?? source?.msg;
  if (typeof message !== 'string') return fallback;
  const text = message.trim();
  return text && text !== 'success' ? `${fallback}: ${text}` : fallback;
}
