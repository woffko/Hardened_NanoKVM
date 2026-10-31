import * as api from '@/api/application.ts';
import { getAppUpdateJob, removeAppUpdateJob, setAppUpdateJob } from '@/lib/localstorage.ts';

export type AppUpdateOutcome = 'committed' | 'rolled-back' | 'unknown';

const POLL_INTERVAL_MS = 3000;
const POLL_DEADLINE_MS = 20 * 60 * 1000;

// The message that stays on the page, or null when the update committed and the
// page reloads into the new version. Any other reload would wipe the report.
export function appUpdateMessage(outcome: AppUpdateOutcome, failed: string): string | null {
  if (outcome === 'committed') return null;
  return outcome === 'rolled-back' ? failed : 'settings.update.outcomeUnknown';
}

// The transaction of an update that this browser submitted and has not seen end.
export function pendingAppUpdate() {
  return getAppUpdateJob();
}

// Follows the installer's transaction until it commits or rolls back. The
// installer stops this backend and starts the new one for its trial, so failed
// requests are waited out. The new backend has no session yet: its 401 reloads
// to the login page, and the stored transaction lets the update page finish
// the report after login.
export async function followAppUpdate(transactionId: string): Promise<AppUpdateOutcome> {
  setAppUpdateJob(transactionId);
  const deadline = Date.now() + POLL_DEADLINE_MS;
  let outcome: AppUpdateOutcome = 'unknown';
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
    const observed = await observe(transactionId);
    if (observed) {
      outcome = observed;
      break;
    }
  }
  removeAppUpdateJob();
  return outcome;
}

async function observe(transactionId: string): Promise<AppUpdateOutcome | null> {
  try {
    const rsp = await api.getUpdateJob(transactionId);
    if (rsp.code !== 0 || !rsp.data) return null;
    if (rsp.data.state === 'unknownOrExpired') return 'unknown';
    if (rsp.data.state !== 'observed') return null;
    if (rsp.data.phase === 'committed') return 'committed';
    if (rsp.data.phase === 'rolled-back') return 'rolled-back';
    return null;
  } catch (err) {
    console.log(err);
    return null;
  }
}
