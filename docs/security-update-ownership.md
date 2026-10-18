# App/system update work ownership

This documents the implemented in-process coordinator, not a claim that C1,
durable installation, raw restore or configuration quiescence is complete.

## Shared admission and observability

One `AppState.updates` coordinator is shared by cloned HTTP/HTTPS state. It
serializes app online/offline work with system download/install/rollback/confirm.
There are no longer separate app/system `Mutex<bool>` admission domains. Busy
requests return the existing API conflict code and the active 128-bit random
operation ID. The ID is public diagnostics, not a signature, capability or
durable authorization ticket.

Authenticated `GET /api/application/update/status` returns `active` and `last`.
System status also includes the same snapshot in `updateOperation`. Only one
active and one last status are retained: ID, fixed operation kind and fixed
phase. No payload/path/private error/configuration data is stored in this view.
`running` means ownership remains; `finished` means request work returned success,
not that a raw writer, reboot, native services or restoration were accepted.
`failed` includes abandonment before work starts, panic and callback/restart
errors. Receipts are in-memory and disappear on process restart.

## Ownership lifecycle

1. Acquire admission before staging/install work. The coordinator registers the
   operation before any job starts. Poisoned coordination fails closed.
2. `UpdateOwner::run` starts runtime-owned work; the HTTP future waits only on a
   oneshot reply. Dropping that reply receiver does not cancel the job. Existing
   success/error response shapes are preserved; clients do not need to implement
   a new asynchronous submission protocol merely to receive the old response.
3. Each `UpdateOwner::blocking` callback owns a private share of the operation.
   Dropping an awaiting future cannot authorize a competing update while the
   callback still runs or unwinds. The complete Drop guard is moved into the
   callback, not an individual captured status field. Queued work also owns it.
4. A blocking error/panic records sticky failure before releasing that share.
   Discarded callback/reply result values are cleaned up while ownership is
   still held; a cleanup panic cannot be reported as success.
   A normally delivered result does not retain the callback's lease. Future
   cleanup-sensitive guards must be consumed inside the callback or carry their
   own work ownership; ordinary returned upload files have no deferred writes.
   Later root-task success cannot overwrite an already observed child/restart
   failure. Public status does not reproduce panic or callback error text.
5. App upload create/write/sync, hashing, install and exact cache cleanup run
   through owned blocking callbacks. Offline reception is bounded to the existing
   archive limit and a fifteen-minute total timeout. Interrupted/incomplete
   bodies do not reach installation; pending filesystem work retains admission.
6. App restart is scheduled **inside** the registered worker, before it replies,
   and owns its share across the delay and restart command. Lost HTTP responses
   cannot skip restart scheduling or open a second-update gap in that delay.
7. Only the last owner releases active admission. Follow-up ownership must not
   be sent back through the HTTP reply and then scheduled by a cancelable handler.

System progress normalization is now read-only. It may return a diagnostic
failure for stale interrupted work but does not overwrite/delete a concurrently
updated progress file. A currently registered system operation is not declared
stale solely because the wall clock changed or a legacy raw process was not yet
visible in `/proc`.

## Explicit remaining boundaries

- This is one-process coordination, not a protected cross-process lock, durable
  install journal, idempotency receipt or power-loss recovery protocol. A new
  backend process cannot infer old job success from these in-memory statuses.
- Existing app staging/extraction/swap is still the legacy path, including its
  writable-p3 cache/provenance and rename/recovery limitations. Work ownership
  alone does not authenticate that filesystem or close the USB trust boundary.
- The legacy raw shell writer is still launched separately. Its handoff/reap,
  immutable image descriptors, protected ticket, retained runtime and early
  fail-closed restore are not implemented by this coordinator. A system request
  finishing after launch is not the raw transaction finishing.
- The old command helper's timeout, pipe-drain and child-reap semantics remain
  a separate gap. A callback lease is not proof that every process it started
  has been reaped. Cancellation-safe process ownership must be wired before
  claiming complete raw/app transaction acceptance.
- Account/password, network, firewall rollback, time/syslog, local terminal,
  scripts, optional-app workers and other configuration writers do not yet
  acquire a shared quiescence permit. No preservation snapshot may claim those
  writers are stopped merely because update admission is held.
- No generic abort handle is exposed. Explicit Stop must use phase-aware
  cancellation plus child/work-owner join, not HTTP disconnect, dropped
  `spawn_blocking` handles or killing an irreversible raw write midway.
- Direct future-cancellation and handler-admission fixtures are host evidence,
  not physical install, HTTP/1 FIN/RST, HTTP/2 reset, reboot or target gates.

The complete restore contract and remaining writer gates are in
[security-raw-restore-transaction.md](security-raw-restore-transaction.md).
