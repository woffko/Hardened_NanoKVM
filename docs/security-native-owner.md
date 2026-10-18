# Native process owner: kernel scope, integration pending

`nanokvm-native-owner` is a separate single-threaded executable, not a subreaper
inside the asynchronous backend. It provides one fresh process-tree lifetime.
It is **not packaged, launched by S95, deployed, or used for production capture
yet**. Existing native services and watchdogs therefore remain unquiesced.

## Implemented boundary

Before launch the owner requires an anonymous Unix socketpair, exactly one
thread, no pre-existing children, default SIGCHLD disposition, and no extra
inherited descriptors. Its private control duplicate is CLOEXEC and child stdin
is `/dev/null`. Production entry additionally requires root and the socket peer
credentials of its direct parent. Only two fixed native roles are accepted:
`kvm-system` and `hwmon`, with the existing explicit vendor loaders/library path.
There is no generic shell/program/path, environment selector or fixture fallback.

The owner enables the kernel child-subreaper property and checks actual pidfd /
`waitid(P_PIDFD)` support before starting native work. Subreaper adoption survives
ordinary daemonization, including `setsid`; it does not itself stop a process.
See [Linux subreaper semantics](https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html)
and [pidfd identity/lifetime](https://man7.org/linux/man-pages/man2/pidfd_open.2.html).

Stop or controller EOF starts TERM, followed by KILL after two seconds. Proc child
numbers only nominate candidates: a freshly opened pidfd must pass kernel
`waitid(P_PIDFD, WNOWAIT)` child-relationship validation before signaling. No PID
file, integer-PID kill, process-name match or process-group membership supplies
authority. Reparented descendants are discovered and reaped by the same owner.
Wait flags include Linux `__WALL` for clone children with non-SIGCHLD exit signals.

Only kernel `ECHILD` after draining waitable exits permits a completion message.
Normal leader exit still cleans/reaps remaining descendants. A cleanup error is
sticky; there is no second short deadline that abandons surviving children.
Controller timeout/EOF is not a synchronous join: a caller must retain the
transaction/maintenance lease until the owner reports closure and itself exits.
Kernel D-state or permanent cleanup I/O failure can prevent bounded completion.

The private socket carries one `R` after spawn. Controller sends `S` to stop;
EOF also stops. After complete reap the owner sends `D` plus one result byte:

| Byte | Meaning |
| --- | --- |
| 0 | Explicit Stop/EOF, including a preclosed control before launch |
| 1 | Observed natural successful leader exit, tree subsequently reaped |
| 2 | Observed natural unsuccessful leader exit, tree subsequently reaped |
| 3 | Observed runtime/control/cleanup error, tree subsequently reaped |

Readiness is not a successful native-service start or health readback. No message authenticates a
raw update, image, settings snapshot, transaction or durable recovery state.
There is no adoption of arbitrary already-running processes. This is not a
hostile-root filesystem/network/capability sandbox: trusted fixed program origin
and the separate local-administration privilege boundary remain required.

## Verification and remaining integration

Host subprocess fixtures execute the same scope code in fresh processes. They
exercise direct/daemonized/stopped children, ignored TERM with escalation,
controller disconnect/invalid input, natural exits, descriptor isolation,
preclosed/named controls, pre-existing children/extra fds/multiple threads,
unrelated live-process rejection and fixed production argument rejection.
No actual KVM program, network service or device is run. A dedicated unusual
clone-exit-signal scenario, forced owner death and vendor-kernel runtime checks
are not yet accepted from these fixtures.

## Controller-side sibling ownership

`native_owner::controller::Group` now owns the two fixed native roles as sibling
owner processes. It never installs a subreaper in the async backend and has no
public arbitrary-command/path/environment selector. Production commands select
only `/kvmapp/server/nanokvm-native-owner --scope <fixed-role>`. The controller
is compiled and used by the broker component, but has **no packaging/S95 switch yet**.

`begin_drain` moves the complete launch capability into a non-cloneable `Drain`
before sending Stop to every cell. While retained, no `Group::start` capability
exists. Explicit `try_resume` returns it only after every cell has all three:
an unambiguous complete `D` receipt, matching direct-owner exit status/reap, and
control EOF. Readiness is only process spawn, not native service health. A caller
deadline leaves the same drain pending; it must retain and continue polling that
owner. No cleanup deadline kills the subreaper or declares successful closure.

Missing/truncated/duplicate/unknown protocol, a receipt/exit mismatch, or owner
death without a receipt makes ownership sticky-uncertain. The group requests
Stop on siblings and refuses new starts/resume. Even reaping all direct owner
processes does **not** clear uncertainty or prove their descendants are gone.
Dropping a controller/drain sends Stop/EOF without respawn but forfeits the
receipt and join; it is not a maintenance success path. A real lifecycle broker
must retain ownership and journal unresolved intent before any process launch.

Host tests cover two real daemonized trees, parallel Stop, explicit restart after
join, caller timeout/retry, immediate pre-readiness drain, controller drop,
fragmented frames, valid receipt before owner exit, delayed EOF, malformed frames,
missing receipt and forced death of a childless wire stub with a real sibling.
That forced-death fixture tests detection/admission, **not recovery of an orphaned
native tree after killing a real subreaper**. Process-tree size/high-churn limits,
unusual clone exit signals, durable crash recovery and vendor runtime remain open.

## Durable native broker admission

`native_owner::broker::Broker` combines the sibling group with a protected
singleton journal. The standalone `nanokvm-native-broker --serve` now owns this
component through a fixed local protocol. Neither executable is packaged or
connected to S95/watchdogs yet; this is not a replacement for the separate raw
restore ticket or proof that existing production services are quiescent.

The fixed store is `/etc/kvm/native-runtime-owner`: root-owned mode 0700 on the
same rootfs, opened descriptor-relatively with no symlinks, magic links or mount
crossing. A nonblocking exclusive flock uses the stable directory inode, which
is never unlinked. State is one single-link, root-owned mode-0600, fixed 80-byte
record. Its SHA-256 detects corruption, not authenticity; protected location is
the trust boundary. It contains only format, boot epoch and Active/Closed/
Maintenance phase, not credentials, process-number authority or raw-update
authorization.
The closed restore allowlist does not preserve/import/delete these runtime
authority members; capture and forged write/absent-archive tests cover state,
temporary state and the control socket member name.

Before the first possible native launch, Active is written to an exclusive
temporary member, file-synced, renamed, and directory-synced. The journal lease
stays owned while native work and the retained drain exist. Closed is published
only after every controller scope proves complete closure. Maintenance instead
persists across that closure: stopping native work does not authorize new work
while a caller may still be preparing a raw handoff. Only explicit resume from
the retained owner can publish Closed and reopen native admission.
`Resume::Retained` keeps ownership when closure/publication is incomplete or
uncertain; it never implicitly resumes. Drop merely releases the kernel lease,
preserving Active or Maintenance.

| Acquired store observation | Native admission |
| --- | --- |
| No record, or valid Closed | Publish current-boot Active before launch |
| Current-boot Active or Maintenance | Refuse: previous ownership is unresolved |
| Valid record from another boot | Old process lifetime ended; expose prior-boot observation |
| Corrupt/unsafe state or leftover temporary member | Refuse; preserve evidence |

The live epoch comes only from bounded kernel `/proc/sys/kernel/random/boot_id`
reading with procfs checks, using the existing nonzero restore-ticket UUID
parser. There is no production path/boot-ID/environment override. A different
boot ID proves only that old native processes cannot still be alive. **It does
not authorize startup before early restore, mark boot-good, validate images,
resolve raw journal state, or allow partition writes.** Those integration gates
remain mandatory. Rootfs replacement can destroy this journal/lease; this code
does not solve the retained immutable runtime and raw handoff requirements.

Publication errors poison the live store. A leftover temporary member is not
removed automatically, and missing PID/socket/name is never used to clear Active.
Reopening may accept a complete Closed record after an ambiguous final fsync,
but only the controller's proven drain can attempt that Closed publication.
An explicit recovery component now handles native journal interruption after a
verified new kernel boot, as described below. It is not connected to init or a
device recovery UI yet; production lifecycle/restore gates remain mandatory.

Host verification injects I/O failures and kills real journal-owner subprocesses
at six publication boundaries. Broker tests check pre-launch intent, retained
drain, missing receipts and cleanup-publication failure, plus a real dedicated
subreaper with a daemonized native fixture while the journal descriptor is held.
These are not power-cut tests, vendor runtime evidence or device acceptance.

## Local lifecycle protocol, not raw-write authority

The daemon listens only at the protected journal directory's `control.sock`.
The journal flock remains the singleton authority. A stale socket is removed
only after journal acquisition has accepted the state, never to clear unresolved
ownership. The endpoint is mode 0600, opened through the pinned parent directory;
cleanup checks its exact device/inode and preserves a replacement member.
Listener and accepted/client descriptors are CLOEXEC.

Both ends verify kernel `SO_PEERCRED` root UID. Requests have fixed 16-byte frames
with a closed operation set, reserved-byte validation and connection-local serials.
At most 16 clients are retained; I/O is nonblocking with bounded work per loop.
An exact duplicate of the last request returns its cached response without
executing again; conflicting replay, gaps and invalid frames close the connection.
There is no generic shell, path, environment, raw writer or settings import opcode.
Root peer identity is **not** executable attestation or a hostile-root sandbox.
The later unprivileged picoclaw/admin capability split remains separate work.

The daemon owns both sibling native roles and desired-role retries. `EnsureKvm`
and `EnsureHwmon` request admission, not health acceptance. Pause consumes all
launch capability before draining and durably records Maintenance. Only that
same live connection may explicitly resume after proven closure. Caller EOF,
protocol failure or disconnect leaves maintenance abandoned, disables respawn
and denies takeover by another client. A maintenance owner is not evicted by the
ordinary five-second idle budget; abandoned state has no implicit expiry.
For a pending response, that transport budget starts after synchronous request
work has produced the reply. Spawn/journal latency must not expire a newly
prepared response before its first write. Partial I/O still updates activity;
a stalled non-owner receiver remains bounded by the same idle limit. This does
not make synchronous filesystem/spawn work nonblocking or give the entire
daemon a hard scheduling deadline.
This is a trusted-root management endpoint: a root peer can keep one of the
bounded slots occupied with partial-frame progress. There is no absolute frame
deadline or availability guarantee against hostile root. Do not expose this
transport directly as the later unprivileged picoclaw interface.

`Channel` retains partial sends/reads and the outstanding serial across caller
deadlines. It refuses replacement of an unresolved operation and poisons itself
on invalid/lost replies. Reconnecting is not permission to replay an operation
whose outcome is unknown. A future maintenance transaction must retain this
channel and the independent raw transaction authority throughout its lifetime.

`nanokvm-native-ctl` accepts only `status`, `ensure-kvm`, `ensure-hwmon` and
`shutdown`. There is deliberately no short-lived pause/resume command: exiting
would lose the retained maintenance connection. Shutdown reports completion only
after the proven drain/Closed state; the daemon may exit after flushing Stopped.
A CLI deadline or lost reply reports unknown completion without killing the
daemon. No valid production daemon invocation is used in host CLI tests.

Host private-directory fixtures cover real Unix socket exchange, fragmented I/O,
serial/replay rejection, actual peer UID mismatch, foreign-client denial,
maintenance EOF and durable reopening refusal, and safe endpoint cleanup.
A separate real subreaper fixture holds journal/listener/client descriptors while
launching and draining a daemonized tree to check descriptor isolation. These
tests do not execute production native roles or establish target runtime health.

## Explicit native journal recovery

`nanokvm-native-recovery` accepts only `status`, `prepare` and `complete`, with
fixed protected paths and kernel boot identity. It is built but **not packaged,
deployed or automatically called by S95**. No force/reset/path/epoch override is
accepted. A live broker's flock refuses recovery; socket/PID absence does not
replace that lease. Status does not create missing journal storage and is not
permission to start services or write partitions.

Normal same-process maintenance resume still uses the retained IPC connection
and proven native drain. Explicit recovery is for an unavailable owner or
incomplete journal where descendant closure cannot be reconstructed. Without
cgroups/PID namespaces, a new kernel boot is the supported proof that those old
process lifetimes ended; the CLI does not claim an orphan-tree adoption protocol.

| Recovery step | Native admission |
| --- | --- |
| `prepare` | Persist root-only `recovery/boot-<kernel-UUID>-<checksum>`; no stop, reboot, repair or start |
| Same boot, even after owner/socket disappears | Refuse completion and normal admission |
| Different kernel boot with a valid fence | Permit explicit native recovery, not raw restore |
| `complete` | Quarantine exact old members, publish Closed, archive the fence; no service launch |

Any object at the fixed `recovery` name blocks normal broker admission before
state parsing. A fence is a protected same-rootfs mode-0700 directory, with one
canonical boot-UUID/checksum empty mode-0600 file. The domain-separated SHA-256
checksum detects valid-looking epoch-name corruption; it is not authentication.
An interruption before that marker can
be completed by repeating prepare, but cannot grant readiness. Unknown/malformed
members, links, unsafe permissions or conflicting receipts fail closed.

After a different boot, completion moves only `state`, `.state.next` and
`control.sock` into `recovery/evidence/` with no-replace renames, or durably records
their original absence. It never follows those original objects or copies their
content into new authority. Both directories are synced before the quarantine
receipt. Derived Closed bytes are written to an anonymous rootfs `O_TMPFILE`,
file-synced, then linked via its own pinned descriptor through verified procfs;
there is no partial named-file fallback or caller-selected magic link. The file
identity/length/link count and directory sync are checked before removing the
active fence. Recreated runtime members are refused before and after publication.

Finally the whole fence is renamed, without replacement, to
`recovered-<original-boot-UUID>`. Original evidence remains on the private rootfs;
no recursive cleanup or overwrite of an existing archive is performed. A crash
during quarantine/publication can resume the same fenced operation, including
after another reboot. Malformed evidence, unexpected recreated members or an
archive-name conflict require administrator inspection; there is no broad
automatic repair or `--force` path. If root compromise is suspected, use trusted
reflash and separate credential rotation rather than treating journal recovery
as system cleanup.

Before any operator reboot, independently inspect/settle raw/app/restore state
and ensure management/recovery access. **The CLI never requests a reboot.** Its
success resets only native admission: it does not resolve a raw ticket/pending
install, provision an account, mark boot-good or authorize partition writes.
Independent early-restore/startup admission must still run before native starts.
The control is cooperative trusted-root management, not protection from a
non-cooperating root process or an already compromised OS. None of the runtime
journal, fence or archived evidence is accepted by settings capture/import/delete.

Host tests inject I/O failures and kill actual recovery subprocesses at ten
boundaries, check same-boot refusal, replay after another boot, live-owner Busy,
read-only status, unsafe/foreign members, exact inode/byte preservation and
unexpected source recreation. Boot IDs are synthetic only in private unit
fixtures; production has no override. These tests are not physical reboot,
power-cut, vendor-filesystem or complete product recovery acceptance.

Build all four static RV64 executables with
`server-rust/scripts/build-native-owner.sh`. The script rejects dynamic loaders,
shared-library dependencies and wrong ELF architecture. This is not app/full
pipeline reproducibility or target execution evidence. The ordinary package
builder intentionally does not include these unused components yet.

Remaining work is production lifecycle and recovery integration: close
admission to respawners, stop/join watchdog work, then stop/join native services and settle
pending AP attempts. Do not naively nest an independent service owner below a
watchdog subreaper: that creates ownership/teardown coupling, not independent
service lifetimes. Broker commands, app restart and raw handoff must explicitly
preserve the correct owners and immutable runtime provenance.

The integration must record unresolved/crashed ownership outside mutable p3 and
fail before partition writes. A dead owner or EOF without a complete receipt
cannot establish that its descendants stopped. Parent/controller failure, owner
SIGKILL/OOM, production recovery integration, exact vendor program behavior and physical
acceptance remain open. Cgroups/PID namespaces are not assumed or enabled.

C1, complete service closure, canonical multi-file settings capture, retained
raw writer/ticket/early restore and production capture remain open. See
[state writers](security-state-writers.md) and
[update ownership](security-update-ownership.md).
