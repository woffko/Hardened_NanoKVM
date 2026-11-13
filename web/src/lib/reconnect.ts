// After an application update the backend restarts into the new build. The
// page used to reload blindly 12 s later, whether the install had failed or
// not: a failure vanished behind the reload, and a slow restart showed a
// browser error page. Now it waits for the restart to begin and for the
// backend to answer again, within a bound, and reports when it does not.
import { getBaseUrl } from '@/lib/service.ts';

export type ProbeResult = 'ok' | 'unauthorized' | 'server-error' | 'unreachable';
export type ReconnectOutcome = 'back' | 'timeout';

export interface ReconnectOptions {
  /** Pause between two probes. */
  interval: number;
  /** How long to wait for the restart to begin before assuming it is done. */
  restartGrace: number;
  /** Total time to wait before giving up. */
  deadline: number;
}

export interface ReconnectClock {
  now(): number;
  sleep(ms: number): Promise<void>;
}

export const DEFAULT_RECONNECT: ReconnectOptions = {
  interval: 2000,
  restartGrace: 15000,
  deadline: 120000
};

export const browserClock: ReconnectClock = {
  now: () => Date.now(),
  sleep: (ms) => new Promise((resolve) => window.setTimeout(resolve, ms))
};

/**
 * One look at the public health endpoint, classified; never throws. A
 * changed address or certificate looks like an unreachable device here: the
 * browser does not tell a fetch why the connection failed.
 */
export async function probeHealth(
  fetchImpl: typeof fetch = fetch,
  base: string = getBaseUrl('http')
): Promise<ProbeResult> {
  try {
    const response = await fetchImpl(`${base}/api/health`, {
      cache: 'no-store',
      credentials: 'same-origin'
    });
    if (response.status === 401 || response.status === 403) return 'unauthorized';
    if (!response.ok) return 'server-error';
    const body = await response.json().catch(() => null);
    return body?.data?.status === 'ok' ? 'ok' : 'server-error';
  } catch {
    return 'unreachable';
  }
}

function up(result: ProbeResult): boolean {
  // A backend that answers at all is back; a revoked session shows the login
  // page after the reload, which is the honest outcome for it.
  return result === 'ok' || result === 'unauthorized';
}

/**
 * Wait for the backend restart that follows an accepted install: first for
 * the old backend to stop answering (or `restartGrace` to pass, in case the
 * restart was quicker than one probe), then for the new one to answer. Every
 * probe is reported through `onProbe`.
 */
export async function waitForBackendRestart(
  probe: () => Promise<ProbeResult>,
  options: ReconnectOptions = DEFAULT_RECONNECT,
  clock: ReconnectClock = browserClock,
  onProbe?: (result: ProbeResult, elapsed: number) => void
): Promise<ReconnectOutcome> {
  const started = clock.now();
  let wentDown = false;
  for (;;) {
    const result = await probe();
    const elapsed = clock.now() - started;
    onProbe?.(result, elapsed);
    if (!wentDown && !up(result)) {
      wentDown = true;
    }
    if (up(result) && (wentDown || elapsed >= options.restartGrace)) {
      return 'back';
    }
    if (elapsed >= options.deadline) {
      return 'timeout';
    }
    await clock.sleep(options.interval);
  }
}
