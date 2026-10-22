# WebRTC admission and session lifetime

This is a component design and host-test boundary, not device or release
acceptance. The full RC12 remediation plan and the development raw-install
barrier remain unchanged. Other transports, native capture ownership,
privileged jobs and PicoClaw task generations have separate remaining gates.

## Admission and signaling

Each `AppState` owns one WebRTC manager. Admission is checked before the
WebSocket upgrade and before peer construction. Saturation returns HTTP 503;
it does not start a queued peer. The fixed peer/task arrays hold at most eight
entries. Per-frame media snapshots use the same fixed capacity, not a growing
map or a newly collected vector.

The retained producer waits between clients and while H264 capture is disabled;
that idle state does not repeatedly overwrite another mode's capture status.

The optional `security` configuration fields have these defaults and valid
ranges. Older configuration files inherit the defaults. Invalid explicit
values fail configuration loading, trial startup and authenticated restore;
they are not silently clamped. Restore preserves nondefault supported values.

| Field | Default | Valid range |
| --- | --- | --- |
| `webrtc_max_peers` | 2 | 1–8 |
| `webrtc_max_message_bytes` | 65536 | 1024–262144 |
| `webrtc_signals_per_second` | 32 | 1–128 |
| `webrtc_max_ice_candidates` | 128 | 1–1024 |

The message bound applies to WebSocket messages and frames, including binary
signaling. A per-connection one-second window counts control frames too. A
window boundary can admit two adjacent bursts; this is not a global token
bucket or a measured device capacity claim.

Separate fixed connection budgets are 48 KiB for the JSON-encoded SDP data,
4096 bytes per candidate and four offers. Inline SDP candidates and trickled
candidates share the total ICE budget. SDP validation uses the same pinned
library parser as negotiation and admits one video media section with an offer
type; audio/data channels and additional tracks are not application features.
Budget/parse failures end that connection, not the user's other transports.
Renegotiation beyond four offers requires a new admitted connection.

The current browser client creates one receive-only video transceiver, sends
one initial offer, trickles candidates and sends a heartbeat every 60 seconds.
Its existing event names and JSON-in-string data encoding are preserved. There
is no new short idle timeout that would conflict with its heartbeat interval.

## Authority and cleanup ownership

The route captures the credential-free `TransportSession` after the existing
firewall and Origin checks. Authority combines that live session with a
connection-local latched stop. Logout/revoke/expiry is observed by signaling,
media fanout and RTCP. A new login with the same username has an independent
lifetime. The existing explicit two-switch authentication-disabled mode remains
an intentional bypass of the parent web session, not of local stop/shutdown.

The manager retains each peer task and the single media-producer handle. The
upgrade callback only registers its owner; peer cleanup does not depend on a
caller continuing to await an HTTP request. Shutdown stops admission, ends
connection access, stops the producer and joins the retained handles. Polling
never takes a pending handle out of the registry. Canceling a shutdown waiter
does not cancel cleanup; a later waiter resumes joining the same owners.

Peer setup and admitted negotiation operations are retained to completion when
authority ends. The browser close is attempted separately with a 250 ms bound;
the setup result is still collected and any returned peer is cleaned. An
admitted operation/packet cannot be retracted, but no next negotiation step,
callback enqueue, RTCP keyframe request or new media write is authorized by a
stale client snapshot. No session lock is retained through network/native I/O.
Keyframe requests, from RTCP PLI/FIR or a new direct viewer, are accepted at
most once per second for all viewers together. A peer flooding PLI/FIR cannot
make the encoder reconfigure several times a second, while loss recovery
stays prompt.

The signal queue has 64 entries. Callbacks use nonblocking enqueue; saturation
requests local stop rather than awaiting a receiver during peer teardown. The
receiver is closed before cleanup. Media-write errors request stop and do not
run a second concurrent peer close. The sole normal peer owner joins its RTCP
reader and then awaits the actual peer close without timing out that future.

Pinned `webrtc` 0.17.1 sets its closed flag before asynchronous cleanup finishes;
that flag alone is not cleanup proof. Its never-sent RTP sender can also miss a
stop notification issued before the first read. The app's RTCP reader observes
its own latched stop independently and its actual task is joined.

Admission covers setup, active use and cleanup. A successful join/close releases
capacity. A failed/panicked owner or uncertain cleanup pins capacity and fences
new peer admission until process recovery. This is an explicit availability
tradeoff, not a successful-stop acknowledgement or an automatic replay policy.
A hanging library operation remains owned and can keep shutdown pending; it is
not turned into success by an arbitrary timeout.

The process signal path joins WebRTC before attempting video deinitialization.
An uncertain WebRTC result exits nonzero without claiming safe video deinit.
This does not prove full backend/native shutdown: direct H264, MJPEG, PTY,
PicoClaw and other process/error-exit paths still need their own acceptance.

## Host evidence and remaining acceptance

`webrtc_policy` and `webrtc_stream::lifecycle_tests` cover admission pinning,
defaults/invalid limits, signal budgets, stale session clones, same-name login
isolation, authenticated real loopback WebSockets, Origin rejection, overload,
rate/oversize closure, idle revoke/expiry and positive capacity recovery.
Local unconnected real peers use no STUN/TURN. The stop-before-first-read case
is reproduced against the pinned library and the app reader is then joined.

Gated synthetic tests separately cover browser closure before an admitted setup
future completes, canceled shutdown waiters, uncertain/panicked owners and the
idle retained producer. These do not simulate a successful connected RTP/DTLS
session or prove device video/capture performance. Detailed command receipts
and any failures are kept in the local remediation ledger/evidence directory.

Current host checkpoint has 19 passing focused tests and a successful locked,
offline production linked RV64 build. Helper bindings, ten root/bootstrap and
one frozen-startup host fixture also pass; RV64 helper bytes are fixture data,
not executed on the host. Clippy adds no warnings; 31 pre-existing
warnings remain. The full aggregate is NOT accepted: three native install/recovery
timing/readiness tests failed, so later harnesses did not execute. Focused WebRTC
success does not resolve those failures.

Still required: connected-peer/backpressure/packet-path tests, actual process
signal integration checks, authenticated device
WebRTC/video/HID/mode-switch acceptance, full app/native
shutdown and the original reproducibility/update/physical/release gates. Do not
close M3, M11 or the full plan from these component tests alone.
