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

### App installer lease handoff foundation (not activated)

The Rust library now provides a one-shot app-job handoff of UpdateEX plus the
enrolled writer admission/activity EX barriers. It is not yet used by the app
installation route and does not submit or authorize an installer, candidate,
slot swap or restart. The legacy app swap/first-restart gate remains OPEN.

`UpdateOwner::prepare_install_handoff` requires an online/offline application
operation with real process admission and a retained WriterDrain. Before any
descriptor can be exported, the original lock switches permanently from explicit
unlock-on-Drop to last-open-description release. A second export is rejected.
SCM_RIGHTS passes the same open file descriptions, so simply duplicating a normal
lease without this change would let the old backend's destructor unlock the
worker's lease. Failed or ambiguous sends do not revert that switch. The original
frontend owner still holds UpdateEX until its final share disappears; the
handoff itself retains a frontend share while it remains in the sending process.
An unrelated concurrent fork may briefly retain a CLOEXEC alias until exec/close.
Transferred leases conservatively remain busy through that interval; a local
Drop or reply is not proof that the kernel admission has already been released.

The transport uses one bounded 72-byte SEQPACKET frame and exactly three CLOEXEC
descriptors over an anonymous local socketpair. Both endpoints check peer UID/
socket type and expected creator PID, with two-second send/receive timeouts.
The received operation ID must match the expected diagnostic ID. The receiver
checks the exact protected `/etc/kvm` domain inodes, same rootfs, root ownership,
mode0700, read-only descriptors and exclusive flock before accepting all three.
No caller-supplied path, root, descriptor number or generic program is accepted.
Receivers release activity, writer admission and finally update exclusion by
closing only; they never explicitly unlock a description the frontend may
still own. Queued rights also retain exclusion until received or the endpoint
is closed. Missing/extra descriptors and truncated/wrong-context packets fail
closed. Only the first packet is consumed; unused queued rights close with the
endpoint. This is not durable operation anti-replay or a result acknowledgement.
The fresh worker must redirect its original stdin socket alias before receiving
or executing anything; adopting a duplicate alone does not close that alias or
drop extra queued rights. The library does not mutate process-global stdio.

This proves admission lifetime, not issuer provenance or durable installation
state. Root peer identity is not executable attestation. The ID is not a secret,
signature, health acknowledgement or a fresh installation receipt. New-process
status/restart acceptance, independent installer activation, authenticated
candidate receipt, journaled publication/health/retirement/rollback and helper
version migration still need integration before this can replace the current
app path. Never release UpdateEX and then reacquire it around backend restart.

The eventual installer worker must be launched by the independent broker as a
sibling of the serving backend scope, not as a descendant of that backend.
Daemonizing a backend child cannot escape its subreaper. An update lease does
not exempt a process from a scope Stop: backend shutdown would still kill a
worker nested inside that tree. The present handoff module launches no worker;
broker-owned delivery, stop authority, app journal/health and durable job status
remain the next integration work rather than a backend-spawned fallback.

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
5. App upload create/write/sync, hashing and install run through owned blocking
   callbacks. Cleanup of a populated stage, when allowed, stays inside the
   install callback; earlier reception failures can drop an empty stage in the
   registered async job.
   Offline reception is bounded to the existing
   archive limit and a fifteen-minute total timeout. Interrupted/incomplete
   bodies do not reach installation; pending filesystem work retains admission.
6. App restart is scheduled **inside** the registered worker, before it replies,
   and owns its share across the delay and restart command. Lost HTTP responses
   cannot skip restart scheduling or open a second-update gap in that delay.
7. Only the last owner releases active admission. Follow-up ownership must not
   be sent back through the HTTP reply and then scheduled by a cancelable handler.

## Private application staging

The remediation source now routes both online and administrative offline app
updates through `/etc/kvm/application-update/stage-<random128>`, not the
configurable `/data` cache. This is source/host acceptance, not a shipped security
release or completed C1. Root, `/etc` and `/etc/kvm` are opened without symlinks,
magic links or mount crossings and require protected root ownership. The fixed
staging parent and each fresh operation directory require mode0700 on rootfs.
An unsafe existing object is rejected, not repaired. No previous stage or p3
cache is reused, scanned, or deleted to prepare a new operation.

The compressed archive is an anonymous rootfs `O_TMPFILE|EXCL`, mode0600. Only
the staging module owns its writable file, with no public pathname or exposed
writable clone. Curl receives HTTPS-only arguments, disabled curlrc, null stdin
and a pipe, not an output filename. The registered job bounds each received
chunk against the signed size before an owned blocking write; short/long data,
nonzero exit and deadline errors refuse installation and reap the fixed direct
child. No stdout retry can append a second response. This is direct-child
supervision, not a claim of generic descendant quiescence.

Online metadata and its detached signature now travel together as their exact
original bytes, including through stable/preview version selection. The install
job reads persisted Config before fetching and again after the archive download;
it reparses and reauthenticates those same bytes against the current key policy
and key file before handing the candidate to the blocking install phase. It
does not fall back to the server's startup Config or reserialize a cached parsed
view as signature input. Metadata is bounded to 64 KiB and signatures to 16 KiB;
metadata/signature curl requests also disable curlrc and restrict redirects to
HTTPS. An unsigned online lab receipt requires the current explicit setting and
an empty signature; it is not administrative offline import.

The authenticated exact size and decoded SHA-512 are checked against the retained
anonymous inode. After sync,
verified procfs is used to reopen that same inode with an independent O_RDONLY
description; the sole writable owner closes before the opaque archive can be
extracted. Extraction never reopens an archive pathname after hashing. The
candidate's bounded regular UTF-8 `version` must be semver; online it must equal
that exact metadata version before any live slot/backup mutation. Version reads
use NOFOLLOW/NONBLOCK and at most 129 bytes, rejecting directories, FIFOs, symlinks
and an oversized file without blocking or loading an arbitrary large value.

After download, the online job now calls the composed `AppState::drain_writers`
boundary (30-second deadline), settling the enrolled firewall rollback owner
before waiting for enrolled activity. Only then does it reread persisted Config
with `Config::read_frozen` and reauthenticate the exact metadata/signature. The
same owned `WriterDrain` survives that blocking read, reauthentication, archive
verification, extraction and the current legacy swap. Offline import acquires
the same barrier after upload, without inventing signed metadata authority.
The barrier moves into the owned install callback, not the HTTP handler; a lost
reply or discarded blocking waiter cannot reopen enrollment during its work.
Busy/unsafe admission or a drain timeout refuses installation. No ConfigPermit
is acquired under the exclusive drain, avoiding self-conflict.

This freezes only cooperating enrolled writers. It does not stop native/S95
services, privileged sessions, scripts, or other unenrolled startup writers.
The barrier currently ends when the blocking install returns, before the
delayed legacy restart: retained native lifecycle, journaled swap and first-start
recovery are still mandatory, not provided by this prerequisite.

App and system metadata now share a descriptor-bound signature verifier. It
captures the selected public key and optional allowlist from protected rootfs
directories, enforcing key ID syntax, regular files, effective-owner identity,
single links, bounded lengths, and non-group/other-writable modes. Every parent
is opened descriptor-relative with no symlink/magic-link/mount crossing. An
intermediate root-owned sticky shared directory is allowed only with ownership
checks on every protected child; the trust root/keyring themselves may never be
shared/sticky. Nonsticky writable ancestors, relative/parent traversal, alias
files and unsafe configured locations fail closed instead of falling back.

Policy/key source identity, mode, link count, length, mtime and ctime are checked
again around bounded reads. The key, exact metadata and signature are each
copied into anonymous rootfs files, synced and reopened independently O_RDONLY
through verified procfs; all writable aliases close before verification. Fixed
OpenSSL arguments point only to `/proc/PARENT/fd/N`, not to mutable configured
source names or named `/tmp` inputs. The command supervisor owns all three
descriptors through pipe cleanup and direct-child reap, including cancellation.
No new unsafe code/dependency, key ID/algorithm or unsigned/manual-import policy
is introduced. Historical absence of an allowlist keeps its existing semantics;
a present malformed/empty/disallowing policy still refuses verification.

This is an in-process signature-input snapshot, not a durable app-slot receipt
or raw-writer ticket. Final install still needs current policy under the writer
freeze. Hostile local root, target mount/procfs/O_TMPFILE acceptance, retained
issuer provenance and independent recovery remain separate obligations.
There is still no durable signed app-slot receipt. The explicit lab-only
unsigned setting, production key IDs/algorithms and manual bridge path are unchanged.
The version-only query still uses its startup Config snapshot; it is status,
not permission to install or proof that policy is still current.

Offline upload deliberately remains an authenticated administrator's manual
import, with external checksum verification as documented for the bridge. It
does not acquire an invented signature proof or fall back from online signature
failure. It uses the same anonymous/readonly archive and private extraction,
rejects multiple `file` fields rather than selecting the last, and retains the
existing fifteen-minute upload deadline and 128 MiB compressed limit.

App extraction admits GNU/ustar directories, regular files and bounded GNU long
names, matching the published packages. The ordinary top-level `MANIFEST.txt`
is allowed alongside the single app root, but is never trust authority. Links,
sparse/PAX/special entries, duplicate file overwrite and other top-level roots
are rejected. Limits are 256 MiB of decoded tar (including padding), 8192 raw
members and distinct output paths including implicit parents, 4096-byte paths
and depth64. All regular outputs sync before installation. Extraction drains
through the gzip footer/CRC and rejects nonzero tar tail, a second gzip stream
or other trailing compressed bytes. The generic system-archive extractor is
not changed by this app-specific parser.

Output names are used only beneath the fresh private rootfs stage. This assumes
a cooperative protected OS, not a hostile local root changing mounts/ancestors.
Before live slot/backup mutation, best-effort cleanup checks the owned stage's
inode/binding and removes only that generated subtree. Once mutation may start,
ordinary failure instead retains the validated candidate, including failure of
backup restoration; only successful completion explicitly consumes the stage
for cleanup. A replaced binding, crash orphan or cleanup failure is preserved;
it is not a success or durable recovery receipt. This in-memory cleanup flag
does not implement restart recovery or authorize reuse of any retained stage.
Production never infers authorization from old staging presence.

Historical retained app 2.0.40, 2.0.41 and corrected bridge 2.0.42 are individually
hash-pinned in a manual host fixture and pass this extraction/structure path
without invoking live install. Host tests also cover readonly descriptors,
unsafe/replaced staging, archive budgets/framing, direct-child error/deadline
reap and lost reply ownership. Actual HTTP FIN/RST/HTTP2 and target filesystem
checks remain separate gates.

The subsequent `/kvmapp`/`/root/old` swap is still the legacy path: it has no
durable journal/early recovery and is not an atomic or accepted crash-safe
transaction. Slot provenance, independent startup recovery and first restart
acceptance must be implemented before claiming WP-04 or C1 complete.

### Independent recovery prerequisite

Buildroot and the SD assembler install a separate `/etc/init.d/S95nanokvm`, but
that script still loads backend/native work from `/kvmapp`; it cannot recover a
missing app directory. Rust recopies bundled init scripts only after it has
already been launched, and exits on required-copy failure. Consequently a
recovery executable bundled only under the new `/kvmapp` cannot close the gap.

Before activating a journaled slot swap, a fixed rootfs recovery/bootstrap
executable and startup gate must be available independently of the candidate.
They must run before the first boot consumer of `/kvmapp`, not merely rely on
late backend startup. Rootfs builds must install this path up front; an installed
bridge must establish/check it before exposing the new swap operation. Missing
or mismatched recovery support must refuse the mutation, not claim that two
renames are recoverable. Unknown/torn journal state must preserve evidence and
must never synthesize authorization from a legacy p3 marker or plain inventory.
The standalone rollback component and static helper build are now implemented
and host-tested. The linked backend compile-binds a distinct app-recovery image,
and packaging/Buildroot preserve and check its exact bytes. Buildroot/SD recipes
now install an independent rootfs copy; target startup attempts atomic app-only
bootstrap without replacing unknown support. Failure keeps management available,
and the target app API rechecks exact independent support/no journal under its
existing admission before legacy mutation; see
[app-slot recovery](security-app-slot-recovery.md). S02/individual app-consumer
gates are now wired and host-tested, with compile-bound critical init scripts and
helper-before-gate publication by the new backend. They are snapshot checks, not
native launch ownership. App archives now use a pinned legacy-S95 delivery view
without premature ancillary gates; full-image staging remains canonical. This
addresses the exact RC12 copier ordering at host scope, not device acceptance.
Pinned v1 predecessors now have a directed forward-publication path under one
live update-admission owner, with atomic exchange and retained old evidence.
Unknown/unsafe support and nonterminal journals refuse migration; missing support
still requires no transaction. This is not automatic old-backend rollback or
protocol-upgrade acceptance. The trusted producer and first-restart/rollback
acceptance remain open. Independent installation has no full target acceptance.
The app API still uses its
legacy swap; no interrupted-install acceptance is claimed from this component.

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
and update admission release occur after explicit direct-child cleanup. Enrolled
account/Config commands additionally retain their permit in the command owner;
other configuration callers still need permit/Stop integration that retains
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

## Separate configuration-writer admission and account/Config enrollment

`AppState.writers` is separate from update admission. Its fixed protected-rootfs
directories use the same root/owner/mode/device/open checks and persistent-inode
rules as the front-end lease: `/etc/kvm/state-writer-admission`,
`/etc/kvm/state-writer-activity`, `/etc/kvm/account-operation` and
`/etc/kvm/configuration-operation`. A writer acquires admission shared, activity
shared, then its serial domain exclusive; after enrollment it releases the
short admission share. Account and Config mutations have independent serial
domains, but both count toward the same activity drain. Concurrent mutations
in one domain fail busy rather than interleaving their read/modify/write work.
Zero-sized role tags keep `AccountPermit` and `ConfigPermit` distinct: Config
enrollment cannot authorize an AccountStore mutation, or vice versa. The
constructor and ownership-sharing machinery remain internal.

`StateWriters::drain` takes admission exclusive before waiting for activity
exclusive. It rejects new enrollment while existing work drains, and returns a
guard that must remain owned through the protected read/capture phase. Timeout,
error or cancellation releases admission without claiming a drained state.
This API is not yet called by a production update/capture path. Do not hold a
future capture barrier across a network download or infer quiescence merely
because an app/system update owns its independent admission lease.

First-account setup, password change and explicitly enabled legacy account seed
are enrolled. AccountStore mutation requires an internal permit; ordinary login
verification remains read-only. First setup rechecks absence under account
serialization before changing native root identity. Existing authorization,
password rules, API success shapes and default-disabled legacy seed remain.
Unsafe/busy writer storage fails closed; no default-account recovery is added.

After validation, a runtime-owned task retains the account permit through native
`passwd`, blocking web-account hashing/publication and configured token revocation.
Lost HTTP replies do not abandon the middle of this sequence. Blocking callbacks
and command owners retain their own shares; dropping their waiters cannot release
writer activity before callback/discarded-result cleanup or direct-child reap.
A delivered callback result does not retain ownership; cleanup-sensitive returned
guards must own a share or be consumed inside the callback. Encoded/decoded
passwords and the duplicated command input are zeroizing; native command output
is not reproduced in account error replies. This is not a general guarantee that
password data has no other copies or that arbitrary command output is safe.

Native and web password publication are **not** an atomic transaction: native
success followed by web-file failure can still leave different credentials.
Web account publication still uses its existing truncate-in-place path, and
rollback/journaling, protected file publication and power-loss recovery remain
required. Enrollment closes lifetime/interleaving gaps, not these failures.

Config enrollment covers all five YAML setters: remote-image download, local
terminal enablement, session duration, raw-update enablement and TLS protocol.
The permit is acquired before reading YAML or doing related side effects and
retained through publication/runtime updates. Blocking read/modify/write work
does not run on the HTTP task. Session duration also retains ownership through
live-session retiming and cookie construction. Lost replies cannot leave that
sequence halfway merely by canceling the handler. Other settings in the
immutable startup Config snapshot are not silently refreshed by this change.

`Config::load` also acquires the Config domain before reading YAML and checking
or generating the persisted session secret. It uses the same kernel locks as
runtime setters across independent backends; busy/unsafe storage fails closed,
not through a rootless startup fallback. The Rust bundled-trust installer now
also enrolls the same Config domain before reading its bundle and retains the
permit through legacy/keyring publication and policy-last publication. Separate
StateWriters instances share the same protected kernel lock namespace. Current
S95 no longer copies trust files: the backend performs this step before serving
requests, including when started outside S95. No key IDs/material/algorithm or
legacy allowlist are changed here.

The exact historical S95 in the RC12 app bridge remains unchanged and still
performs its historical pre-backend trust copy. New locking cannot retrofit that
old executable path. The documented USB-data isolation/reflash restrictions
continue to apply to this first legacy transition; it is not covered by the new
writer freeze. Other startup migration/script writers remain unenrolled.
Ordinary Config getters remain read-only and do not acquire writer admission.

TLS holds its Config permit across certificate generation or the forced
moderate-firewall operation, YAML publication and scheduling reboot. The delayed
reboot task receives the permit before the root worker replies; it retains it
through the delay and the command's direct-child cleanup. Normal capture and
stdin commands both support this retained ownership. No shutdown/process-tree
completion or durable reboot journal is implied.

Config/TLS publication is still **not** a multi-file crash transaction. The
existing YAML rename helper has pathname races and ignores parent-directory
sync errors; session-secret writing remains truncate-in-place. Certificate/key
publication and firewall changes can occur before a later failure or YAML
write error, with no compensating rollback. The existing session-secret read/
regeneration policy is unchanged. Protected atomic publication, error recovery
and target TLS/firewall/reboot acceptance remain required.

Synthetic host fixtures use explicit cfg(test)-only private config paths, not
process-global environment mutation. They check real safe setters, lost replies,
serial conflict/retry without lost fields, session retiming, startup secret reuse,
publication errors and retained command/follow-up lifetime. They do not execute
native firewall, TLS generation at device paths or reboot.

Network API enrollment is described below. Active terminal sessions, scripts,
optional apps and independent native service/background writers are not quiesced.
No coherent preservation snapshot, all-writer freeze, phase-aware Stop/join,
service stop, raw-writer ticket
or retained transaction is accepted from this component. The host fixtures do
not change a live root password or device configuration.

### Owned firewall transition

Standalone firewall set/confirm now enter through the Config serial domain and
runtime-owned work, also serializing against TLS changes. A distinct typed
Firewall permit owns the protected `firewall-operation` kernel lock and common
writer activity. Only an already enrolled Config operation may create this
follow-up, even after new admission closes. There is no gap in activity ownership.

The pending timer keeps the Firewall permit, not the Config serial lock, so
ordinary Config changes and confirmation remain possible during the 60-second
confirmation window. Its controller retains the join handle until completion.
Confirm joins with an explicit confirmation; a replacement first rolls back and
joins the old transition, then publishes a new random transaction ID. The old
timer cannot act on the new marker. Marker identity and all recorded fields must
match the task's original record; their contents do not supply new rollback
authority. Marker reads are capped at1024 bytes, use nonblocking/no-follow open
and require a single-link regular file owned by the backend UID with mode0600;
special files, aliases and broad permissions fail closed. Native commands and
blocking callbacks keep their own permit shares.

`AppState::drain_writers` first closes writer admission, asks the pending firewall
owner to roll back and joins it, then drains the common activity shares under one
deadline. Cancellation/timeout returns no drained guard and does not discard the
pending join handle or command owner. Retry resumes the same cleanup. The
low-level `StateWriters::drain` only waits for activity: it does not settle a
pending firewall transition or diagnose orphan markers. A future capture caller
must use the composed boundary and still close all other source writers.

Unknown/orphan pending markers, marker mismatch, task panic or failed rollback
abort this composed boundary. An observed owner/publication failure is sticky in
the running controller. Explicit Moderate/Baseline selection or the TLS-disable
Moderate operation is a recovery action and can clear it only after successful
publication/application. This is not automatic fallback or confirmation. A second
backend cannot replace a live owner's marker: the kernel Firewall lock survives
the first handler's reply. Confirming a foreign owner is rejected, not forwarded.

Here successful application means the command completed with status0, not that
effective rules were read back and proved correct. The current S40firewall script
can return0/print OK after individual iptables failures; this component does not
fix that service error-propagation/readback gap. It remains a required WP-11
gate, not evidence of effective firewall enforcement or remote reachability.

These are one-process-lifetime guarantees, not durable firewall recovery. The
legacy `/tmp` marker and file rename helper still lack protected durable journal,
crash recovery, complete pathname hardening and directory-sync guarantees. A
backend restart/power loss is not proved safe by this timer protocol. Actual
iptables/interface/TLS/remote reachability and service process-tree completion
remain target gates. No production raw capture consumes the composed boundary
yet. Other producers, especially independent network/init/local privileged code,
remain open.

Synthetic tests exercise real set/confirm handlers, timer expiry, replacement,
lost replies, cancellation/deadline while a fixture command runs, sticky errors,
foreign/orphan marker rejection, already-admitted TLS follow-up and independent
exec ownership. Fixture paths/commands exist only under cfg(test); they do not
alter firewall rules or invoke device services on the host.

### Owned time and syslog settings

Time set, explicit time synchronization and syslog set now use the Config serial
domain and common writer activity. Their runtime-owned root work survives a lost
HTTP reply. Time set owns validation, time JSON, NTP configuration/defaults and
timezone-link publication, then the service action. Sync owns its selected config,
ntpdate and subsequent NTP restart. Syslog set owns JSON, syslog/klogd defaults and
both service actions. Blocking publication and native command cleanup retain
their own shares. Other Config operations receive a retryable conflict while
this serial operation is active; account authorization remains a separate role.

The composed admission/drain waits for these enrolled operations to finish; it
does not cancel them at an arbitrary file/service boundary. A deadline returns
no drained guard while the root owner or direct-child cleanup is still active.
Ordinary status/log readers remain readers, not quiescence owners. Their returned
values are not a coherent snapshot or proof of effective daemon state.

This is not atomic multi-file publication or rollback. A later write/command
failure can follow successful earlier writes. Explicit negative tests preserve
that fact; no coherent-state claim follows merely because activity drained after
an error. Protected publication/recovery and canonical legacy time/syslog capture
plus signed-image regeneration remain required before production capture.

Native service ownership is separate. S49ntp normally waits for its ntpdate child,
but its killed watchdog is not joined, the descendant sleep/process-tree and
timeout boundaries are not closed, and stop does not prove ntpd completion.
S01syslogd/S02klogd also do not join their daemons. Echo-based status paths can
hide native failure. A completed API service command is not daemon-stop/readback
acceptance, especially after timeout. Independent init calls still bypass API
admission. No service script changes or target clock/logging operations are
included here. Fixtures use explicit cfg(test)-only rooted files and commands,
never process-global environment changes or production-command fallback.

### Owned network settings and optional WOL history

DNS/IPv6 changes, authenticated Wi-Fi connect/disconnect, AP credential/request
publication, WOL rename/delete and optional history writes use the Config serial
domain. Runtime work retains admission through the complete file/service chain,
including manual DNS resolver repair and DHCP resolver publication after the
Ethernet restart, and credential removal after Wi-Fi stop. Losing the HTTP reply
does not abandon an enrolled operation or its direct-child cleanup. Other Config
mutations fail busy; no per-file lock gap is introduced.

WOL packet dispatch stays outside local configuration admission. Only after a
successful target action does the API try to save history. Busy/paused or failed
cache mutation is best-effort and cannot turn that successful action into failure.
Cache edits and history insertion share one serialized read/modify/write boundary;
read errors no longer become an empty history that overwrites existing data.
Wi-Fi SSID publication now uses mode 0600 as already used for its password. Route URLs,
DTOs, service arguments and deadlines are unchanged.

AP success still means credentials plus `wifi_try_connect` publication, not
association/IP completion. The native `kvm_system` consumer removes that marker,
calls S30wifi and independently writes connection state; it has no Rust permit.
Ordinary disconnect likewise is not a settlement/join of that native attempt.
S30eth/S30wifi spawn independent DHCP/WPA/AP clients and hooks. Service command
completion is not daemon/descendant closure, effective network readback or proof
that a pending marker was consumed. Before capture, stop/join the respawners and
native consumers and explicitly complete or abort pending attempts.

Multi-file publication still can leave earlier writes after a later failure;
negative fixtures demonstrate this rather than claiming rollback. File/path
durability, canonical legacy network capture and signed-image regeneration remain
open. Synthetic fixtures root fixed paths and commands using a cfg(test)-only
permit, with no environment selector or real-command fallback. They do not change
host/device networking, transmit real WOL packets or test physical connectivity.

## Explicit remaining boundaries

App-slot preparation now consumes an opaque archive-derived candidate together
with the retained app handoff and atomically publishes a complete protected
`prepared` receipt without touching `/kvmapp`. A receiver must bind its three
accepted leases to that exact transaction and old-live/new-staged layout.
The [preparation protocol](security-app-slot-recovery.md#durable-preparation-and-lease-acceptance-not-activated)
and its real exec/fixed-root host test do not activate a broker-owned installer,
journaled live swap, first-start health or terminal retirement. The API still
uses the legacy swap/restart and is not accepted for deployment.

The [native owner component](security-native-owner.md) supplies separate-process
child-tree Stop/reap and sibling-controller drain machinery. Moving its launch
capability into a retained drain closes in-process starts; receipts, owner exits
and EOF are checked independently, and uncertainty cannot resume. This is not
production respawner admission. The broker daemon/IPC component holds a
protected singleton/Active or Maintenance journal across native work and drain,
refuses unresolved same-boot ownership and retains abandoned maintenance. Its
explicit native recovery requires a new kernel boot, preserves old evidence and
never grants raw/restore authority. Current native programs are packaged and
S95 KVM/hwmon source wiring now requires fresh-boot enrollment (see
`security-native-owner.md`). This is not deployed, does not join all writers or
the watchdog, and does not call the composed writer drain/retained raw handoff. A
changed boot epoch resolves only old process lifetime, never raw restore or boot-good. Its
presence does not close the following production boundaries.

- The front-end kernel lease is cooperative cross-process admission, not a
  durable install journal, idempotency receipt or power-loss recovery protocol.
  It does not survive destruction/replacement of rootfs and has not been handed
  off to the retained raw writer. A new backend cannot infer old job success
  from directory existence or these in-memory statuses. Hostile local root
  replacing lock paths/mounts is outside this lease's protection boundary. The
  legacy self-restart can terminate the backend before its init-script child
  finishes; no lock inheritance/handoff to that child is claimed here.
- App staging/extraction now uses protected rootfs and readonly authorized
  archive bytes as described above, but the swap still has legacy rename/
  recovery limitations. Work ownership alone is not a durable slot journal,
  trusted producer, first-restart acceptance or complete USB trust boundary.
- The legacy raw shell launcher and plaintext p3 boot restore are removed.
  Production raw installation returns an explicit development barrier before
  launching a writer or publishing a raw marker. Its required replacement still
  needs immutable image descriptors, protected ticket, retained runtime and
  early fail-closed restore. This temporary unavailability is not acceptance or
  permission to drop raw functionality from the final result. A future request
  finishing after launch must not be mistaken for the raw transaction finishing.
- The command helper now owns normal direct-child timeout/pipe/reap cleanup,
  but is not a process-tree manager, a synchronous Drop join or a protected
  transaction authority. A callback lease alone is still not proof that every
  process it started has been reaped. Raw writer handoff, remaining configuration
  cancellation/permit joining and target service behavior remain separate gates.
- Startup app/native helper preparation now uses one shared update admission
  retained by `BootSupport` through critical consumer-script publication. Native
  support is compile-bound, exact-checked and never replaced by unknown bytes;
  a failed preparation withholds those scripts. This is file-bootstrap ownership,
  not proof of native shutdown, legacy-process transition or a raw-writer lease.
- Other startup writes, independent native network producers, active terminal,
  scripts, optional-app workers and other configuration writers do not yet
  acquire the shared quiescence permit. Account/Config/firewall/time/syslog/network
  API enrollment is partial coverage, not a credential/TLS/config rollback
  protocol. No snapshot may claim
  all writers are stopped merely because update admission or this drain is held.
- No generic abort handle is exposed. Explicit Stop must use phase-aware
  cancellation plus child/work-owner join, not HTTP disconnect, dropped
  `spawn_blocking` handles or killing an irreversible raw write midway.
- Direct future-cancellation and handler-admission fixtures are host evidence,
  not physical install, HTTP/1 FIN/RST, HTTP/2 reset, reboot or target gates.

The complete restore contract and remaining writer gates are in
[security-raw-restore-transaction.md](security-raw-restore-transaction.md).
