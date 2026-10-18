# App/system update work ownership

This documents the implemented work coordinator and cooperative cross-process
front-end lease, not a claim that C1, durable installation, raw restore or
configuration quiescence is complete.

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

## Protected cross-process front-end lease

Every production acquisition also takes a nonblocking exclusive `flock` on the
directory `/etc/kvm/update-operation`. The last work owner holds its descriptor,
including across queued/running blocking work and app restart scheduling. An
independent backend cannot enter another app/system front-end operation while
that kernel lease remains held. Local conflict replies keep the active operation
ID. Cross-process conflict reports another owner but does not invent an ID from
an untrusted/stale file; the bounded status view remains process-local.

The fixed build-owned path is not configurable and is never selected from p3,
cache metadata or a PID marker. Acquisition requires root and opens `/`, `/etc`
and `/etc/kvm` without symlinks, magic links or mount crossings. Parents must be
root-owned directories without group/other write or special mode bits. The lock
directory must be root-owned mode0700 on the same device. Missing lock directory
is created under the pinned protected parent; unsafe existing objects are not
repaired, followed or deleted. Storage/permission errors fail closed; there is
no path-based or in-process-only production fallback.

The lock inode is deliberately never unlinked/rmdir'd on release. All cooperative
contenders reopen that same inode; replacing a live lock name would split the
admission domain. Its descriptor is CLOEXEC; last-owner teardown explicitly
unlocks to avoid a temporary pre-exec inherited alias prolonging the lease.
The kernel releases the lease when the last open-description owner disappears
or on reboot, even though the empty directory persists. After abrupt parent
death a pre-exec fork alias can conservatively prolong busy until it closes or
execs; it is not proof that a child transaction completed. Neither directory
existence nor an inactive local status
authorizes restore, proves success, recovers a transaction or quiesces writers.
The local final receipt can briefly become visible before field Drop releases
the kernel lease; competitors still fail busy during that interval.

Host fixtures use explicit cfg(test)-only constructors and synthetic private
parents owned by the test UID. These constructors and environment-controlled
subprocess probes are absent from shipped code. Handler fixtures live inside
the unit-test module so no fixture bypass enters the public production API.
Independent exec, SIGKILL release, same-inode reuse, unsafe objects and canceled
blocking ownership are host evidence. Target filesystem/kernel admission and
same-device bind-mount negative testing remain separate gates.

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

## Command lifetime within the update worker

`system::command` now gives each capture or stderr-matcher command one runtime
owner. There are no separately spawned stdin/stdout/stderr tasks. Capture runs
direct-child wait, stdin write/shutdown and bounded stdout/stderr drains together
under one wall deadline. Both output buffers retain at most 256 KiB while
continuing to drain; reaching EOF, not merely child exit, is required for capture
success. Blocked stdin or a retained pipe writer cannot escape the same deadline.
The internal copied stdin is zeroizing; this does not claim to clear caller-owned
password strings or make command output safe for arbitrary logging.

On capture timeout/I/O failure, the owner closes its I/O futures, requests kill
of the direct child and explicitly awaits reap before sending a result. A kill
error cannot skip the wait; successful reap accepts a racing natural exit. There
is no second short reap timeout that abandons a still-live direct child. Kernel
wait/I/O failure can still produce a cleanup error or prevent completion; a
command deadline is not a promise of bounded kernel teardown.

The Tailscale login matcher preserves first matching URL, CRLF and final-line
behavior. It bounds each stderr line to 256 KiB, rejects invalid UTF-8/oversized
lines and stops/reaps the direct CLI on a match, timeout or error. EOF without a
match still waits for the direct child under the same deadline. For `passwd`,
an early stdin failure remains secondary to nonzero exit/status output; a zero
exit still requires successful input delivery.

Loss of a command's caller signals the runtime owner to cancel and reap; dropping
the waiting future is **not** a synchronous cleanup join. The registered update
worker is not canceled by HTTP reply loss, so its command timeout/error result
and update admission release occur after explicit direct-child cleanup. Generic
configuration callers still need future permit/Stop integration that retains
quiescence ownership until such cleanup is joined.

Init scripts deliberately daemonize services. No process-group kill or claim of
descendant quiescence is added: surviving daemon children are not update-owned
transactions, and descendants retaining pipe ends cause a bounded capture error.
Runtime shutdown/unexpected task panic remains outside normal Result-path reap
proof. Host tests verify direct-child reap and absence of orphaned pipe readers;
they do not establish target init-script compatibility or physical acceptance.

System progress normalization is now read-only. It may return a diagnostic
failure for stale interrupted work but does not overwrite/delete a concurrently
updated progress file. A currently registered system operation is not declared
stale solely because the wall clock changed or a legacy raw process was not yet
visible in `/proc`.

## Explicit remaining boundaries

- The front-end kernel lease is cooperative cross-process admission, not a
  durable install journal, idempotency receipt or power-loss recovery protocol.
  It does not survive destruction/replacement of rootfs and has not been handed
  off to the retained raw writer. A new backend cannot infer old job success
  from directory existence or these in-memory statuses. Hostile local root
  replacing lock paths/mounts is outside this lease's protection boundary. The
  legacy self-restart can terminate the backend before its init-script child
  finishes; no lock inheritance/handoff to that child is claimed here.
- Existing app staging/extraction/swap is still the legacy path, including its
  writable-p3 cache/provenance and rename/recovery limitations. Work ownership
  alone does not authenticate that filesystem or close the USB trust boundary.
- The legacy raw shell writer is still launched separately. Its handoff/reap,
  immutable image descriptors, protected ticket, retained runtime and early
  fail-closed restore are not implemented by this coordinator. A system request
  finishing after launch is not the raw transaction finishing.
- The command helper now owns normal direct-child timeout/pipe/reap cleanup,
  but is not a process-tree manager, a synchronous Drop join or a protected
  transaction authority. A callback lease alone is still not proof that every
  process it started has been reaped. Raw writer handoff, generic configuration
  cancellation/permit joining and target service behavior remain separate gates.
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
