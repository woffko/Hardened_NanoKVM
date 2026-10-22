# Live web-session lifetimes (development)

This is a partial implementation, not a completed access-revocation or release
acceptance claim. The remaining transports and delegated task authority below
must be integrated before the audit's live-session findings can close.

## One issued session, one lifetime

Every issued web session has a credential-free shared lifetime. Capturing it
does not retain the bearer or CSRF token. Individual logout revokes that exact
lifetime; user-wide revocation ends all matching current sessions. A later login,
including one with the same username, has an independent handle. Losing the
session store revokes its surviving captures without a reference cycle.

Expiry, retiming and revocation serialize under the same short state mutex.
Observed expiry and revocation are terminal; retime cannot revive them or an
already-expired store entry. A valid retime updates existing captures. Timer
wakeups recheck the current deadline instead of ending a renewed session from
an old timer. Wait registration precedes the state check, avoiding lost notices.
No lifetime lock is held during device or network I/O.

The timestamps on a cloned `Session` are response/admission snapshots. Long-lived
consumers must use its lifetime, not a copied expiry timestamp or a fresh lookup
by username.

Expired store entries are removed on validation and at every login. The store
keeps at most 32 live sessions. At the cap, a login revokes the session closest
to expiry, which ends every transport that session captured. There is no
periodic timer: an idle store keeps its expired entries until the next login,
and they hold no credential use.

`TransportSession::capture` requires a live `CurrentSession` when authentication
is enabled. A missing extension is an error, not a bypass. Only the existing
explicit two-switch `auth_disabled` configuration creates an unbounded transport
lifetime. Local administration, terminal policy and loopback internal-token
authorization remain separate boundaries.

## Integrated consumers

| Consumer | Lifetime behavior | Scope limitation |
| --- | --- | --- |
| MJPEG | Revocation interrupts an idle frame receive; liveness is checked before each yielded multipart chunk; completion/drop releases its client guard. | Already yielded/buffered bytes cannot be retracted. With HTTP backpressure, body cleanup can await its next poll or drop. |
| Direct H.264 | Revocation interrupts frame receive and socket-send waiting; transport close is bounded to 250 ms and its client guard is released. | An already admitted/in-flight send can have effects before closure. This is not physical stream or slow-network acceptance. |
| HID WebSocket | Socket/event/queue waits observe the lifetime; pending reports are discarded; the current blocking I/O is joined before owner-specific cleanup. | An already-started device operation is not preempted. Failed compensation remains uncertain, not a verified key release. |
| WebRTC | Live signaling/RTCP/media authority, bounded admission, retained peer/producer tasks and joined normal cleanup. | Connected RTP/backpressure, physical video and complete backend shutdown remain unaccepted; see [WebRTC ownership](security-webrtc-lifetimes.md). |
| Terminal unlock ticket | Consuming a ticket also requires its captured session to remain live. | A ticket admits one terminal connection or one script upload/run. |
| Terminal PTY | The connection waits on the session's lifetime, so logout, a password change or expiry close it with 1008, and a renewal keeps it. Cleanup then signals every live process in the shell's PTY session, by pidfd, before the shell is reaped. | A process that called `setsid()` itself leaves the session and is not reached; there are no cgroups. |
| Pico gateway WebSocket | The chat relay waits on the session's lifetime, so logout, a password change or expiry close it with 1008, even while idle. The relay then cancels the session's admitted Pico calls, releases its Pico session lock and closes the upstream gateway. | Cancelling an admitted call does not preempt an action already in progress. Tasks delegated to the Pico runtime itself are not bound to the web session. |

HID retains separate bounded keyboard and mouse queues and the existing packet
formats. The shared report worker checks authority again after acquiring the
report-bus mutex, immediately before device I/O. A delayed old report cannot
borrow a new login's authority. Explicit later manual input retains last-writer
behavior; old cleanup cannot neutralize a successor's report. A failed write
discards its pending queue, attempts owned compensation and permits fresh input
only if that compensation succeeds. Failed cleanup terminates the worker and
is not recorded as a clean drain. Teardown joins both report workers.

Report admission is the liveness check under that bus mutex. A report admitted
just before revocation can still reach the device afterward; its completion and
owned cleanup must be joined. A revoked flag alone is not a stopped receipt.

Closing a HID connection also discards its pending queue. A report already
admitted to blocking I/O can finish, then compensation runs; no hard syscall
preemption or complete device-reset reconciliation is claimed.

## Remaining integration and acceptance

Pico delegated task authority, pending privileged operations and complete
app/runtime shutdown still need integration. WebRTC now
has component ownership/lifetime integration, but its remaining connected-peer,
backpressure, process-signal and device gates are not closed.
Durable installation jobs must follow their retained transaction stop/drain
protocol; dropping an HTTP future is not a safe cancellation mechanism.

The authenticated administrative loopback bridge must remain usable independently
of a browser session. Binding a web lifetime does not replace immutable task-
generation propagation through browser, upstream runtime and bridge, or a
confirmed full-task Stop acknowledgement. Neither username reuse nor a status
endpoint may let old work refresh its authority.

Host tests cover lifetime transitions, concurrent revoke/retime, capture policy,
ticket consumption, actual MJPEG chunk code, H264/WebSocket with real auth/logout
middleware and a synthetic frame producer, and actual HID socket/report-worker
code with recording ownership sinks. The HID test retains a later authenticated
session's input while old-session cleanup runs. These fixtures do not prove FFI,
physical HID/video, target BIOS/installer/terminal autonomy, slow-network/kernel
I/O bounds, every production route or all session-revocation paths.
