# Waiting for the backend after an application update

Both application update paths of the web interface (the online update and the
offline upload) used to reload the page 12 s after the request, whatever the
request had returned. A failed install vanished behind the reload, a restart
slower than 12 s showed a browser error page, and a restart quicker than the
first probe was never a problem only by luck.

`web/src/lib/reconnect.ts` replaces the timer:

- `probeHealth()` looks at the public `/api/health` once and classifies the
  answer: `ok`, `unauthorized` (401/403), `server-error` (any other
  non-success or an unexpected body) or `unreachable` (the fetch failed). The
  browser does not say why a connection failed, so a changed address or a
  changed certificate looks like an unreachable device.
- `waitForBackendRestart()` probes every 2 s. It first waits for the old
  backend to stop answering (or for a 15 s grace to pass, in case the restart
  was quicker than one probe), then for the backend to answer again; a backend
  that answers at all counts, so a revoked session shows the login page after
  the reload. After 120 s without an answer it gives up.

The update page shows `restarting` while it waits and, on a timeout, keeps the
page with a message that asks for a manual reload and names the address or
certificate change as the likely reason. A failed install (non-zero code, HTTP
error or a failed request) stays on screen with its message; nothing reloads it
away.
The offline upload button refuses a second file while the page waits, as it
already did during the upload itself.

`scripts/test-web-update-reconnect.cjs` runs the real module with a fake clock
and probe sequences: the two-phase wait, the grace for a quick restart, the
120 s bound (a wait that never ends fails the case instead of hanging), a
revoked session counting as "back", the classification of health answers, and
a source check that neither update path reloads on a timer any more and that
the upload refuses a second file while waiting. Five negative controls on the
module and the page each make a case fail. It is not a browser test; the
restart itself is device acceptance.
