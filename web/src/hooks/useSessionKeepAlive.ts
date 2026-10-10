import { useEffect } from 'react';

import { touchSession } from '@/api/vm.ts';
import { getCsrfToken, setCsrfToken } from '@/lib/cookie.ts';

// The session lock counts idle time, so tell the server while the user is at the page. Only
// input counts: the page also polls in the background, and watching the video is not use.
const ACTIVITY_EVENTS = ['pointerdown', 'pointermove', 'keydown', 'wheel', 'touchstart'];
const CHECK_INTERVAL_MS = 30_000;

export function useSessionKeepAlive(enabled: boolean, intervalMs = CHECK_INTERVAL_MS) {
  useEffect(() => {
    if (!enabled) return;

    let lastActivity = 0;
    let lastTouch = 0;
    let busy = false;

    const onActivity = () => {
      lastActivity = Date.now();
    };
    const options = { passive: true, capture: true };
    ACTIVITY_EVENTS.forEach((name) => window.addEventListener(name, onActivity, options));

    const timer = window.setInterval(() => {
      if (busy || lastActivity <= lastTouch) return;

      busy = true;
      lastTouch = Date.now();
      touchSession()
        .then((rsp) => {
          const csrfToken = getCsrfToken();
          // the CSRF cookie expires on its own, so it has to move with the session
          if (rsp.code === 0 && csrfToken && rsp.data?.expiresAt) {
            setCsrfToken(csrfToken, rsp.data.expiresAt);
          }
        })
        .catch(() => {})
        .finally(() => {
          busy = false;
        });
    }, intervalMs);

    return () => {
      window.clearInterval(timer);
      ACTIVITY_EVENTS.forEach((name) => window.removeEventListener(name, onActivity, options));
    };
  }, [enabled, intervalMs]);
}
