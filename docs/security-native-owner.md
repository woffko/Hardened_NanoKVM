# Native process owner: init wiring, acceptance pending

`nanokvm-native-owner` is a separate single-threaded executable, not a subreaper
inside the asynchronous backend. It provides one fresh process-tree lifetime.
All four static native programs are now compile-bound and packaged, with
independent rootfs copies. The current S95 source launches KVM/hwmon/backend only
through the broker after fresh-boot enrollment. This wiring is **not deployed or
accepted on hardware**. Protected app self-restart handoff, watchdog/network-writer
joining and retained installation maintenance remain open; this is not production
snapshot/capture acceptance.

The broker-side [app-install session](security-app-slot-recovery.md#native-closed-publication-and-retained-rollback-not-activated)
now composes accepted app/update/writer admission with durable `Stopping` and a
three-scope drain before slot publication. It retains that fence through explicit
old-slot rollback; no native launch or automatic resume is exposed by the session.
The daemon now invokes it for a validated prepared offer on its separate
app-install endpoint. The ordinary API remains legacy; frozen trial startup,
health/commit/retirement and device acceptance remain required.

## Implemented boundary

Before launch the owner requires an anonymous Unix socketpair, exactly one
thread, no pre-existing children, default SIGCHLD disposition, and no extra
inherited descriptors. Its private control duplicate is CLOEXEC and child stdin
is `/dev/null`. Production entry additionally requires root and the socket peer
credentials of its direct parent. Only three fixed roles are accepted:
`kvm-system`, `hwmon` and `backend`, with explicit vendor loaders/library path.
Backend executes `/kvmapp/server/NanoKVM-Server` directly; no mutable `/tmp`
staging copy or PID-file adoption remains in the current S95 launcher.
There is no generic shell/program/path, environment selector or fixture fallback.

The owner enables the kernel child-subreaper property and checks actual pidfd /
`waitid(P_PIDFD)` support before starting native work. Subreaper adoption survives
ordinary daemonization, including `setsid`; it does not itself stop a process.
See [Linux subreaper semantics](https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html)
and [pidfd identity/lifetime](https://man7.org/linux/man-pages/man2/pidfd_open.2.html).

Explicit Stop starts TERM, followed by KILL after two seconds. Native KVM/hwmon
controller EOF also starts cleanup. Backend controller loss, invalid transport
or natural leader exit instead waits for fixed UpdateEX admission before any
descendant signal; the acquired guard is retained through complete reap. An
already admitted explicit Stop uses the broker's retained permit. Proc child
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
EOF also requests cleanup, subject to the backend update gate above. After
complete reap the owner sends `D` plus one result byte:

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

`native_owner::controller::Group` owns the three fixed roles as sibling
owner processes. It never installs a subreaper in the async backend and has no
public arbitrary-command/path/environment selector. Production commands select
only `/usr/libexec/nanokvm-native-owner --scope <fixed-role>`. The controller
is compiled and used by the broker component and current S95 source.
Startup now bootstraps the four independent native files from compile-bound
backend bytes before publishing consumer scripts. This does not establish
ownership of live legacy processes; a mutable app copy is not an executable-path
fallback. A live legacy transition arms a reboot rather than adopting processes.

`begin_drain` moves the complete launch capability into a non-cloneable `Drain`
before sending Stop to every cell. While retained, no `Group::start` capability
exists. Explicit `try_resume` returns it only after every cell has all three:
an unambiguous complete `D` receipt, matching direct-owner exit status/reap, and
control EOF. Readiness is only process spawn, not native service health. A caller
deadline leaves the same drain pending; it must retain and continue polling that
owner. No cleanup deadline kills the subreaper or declares successful closure.

Missing/truncated/duplicate/unknown protocol, a receipt/exit mismatch, or owner
death without a receipt makes ownership sticky-uncertain. The group requests
Stop on the two native siblings and refuses new starts/resume. It does not stop
a healthy backend merely because KVM/hwmon ownership is uncertain. Backend
protocol failure/drop closes control without fabricating an admitted Stop byte;
the backend owner then uses its update-gated EOF path. Even reaping all direct owner
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
component through a fixed local protocol. Current S95 connects its three fixed
roles to it; this is not a replacement for the separate raw
restore ticket or proof that existing production services are quiescent.

The fixed store is `/etc/kvm/native-runtime-owner`: root-owned mode 0700 on the
same rootfs, opened descriptor-relatively with no symlinks, magic links or mount
crossing. A nonblocking exclusive flock uses the stable directory inode, which
is never unlinked. State is one single-link, root-owned mode-0600, fixed 80-byte
record. Its SHA-256 detects corruption, not authenticity; protected location is
the trust boundary. It contains only format, boot epoch and Active/Closed/
Maintenance/Stopping phase, not credentials, process-number authority or raw-update
authorization.
The closed restore allowlist does not preserve/import/delete these runtime
authority members; capture and forged write/absent-archive tests cover state,
temporary state and both control/app-install socket member names.

Before the first possible native launch, Active is written to an exclusive
temporary member, file-synced, renamed, and directory-synced. The journal lease
stays owned while native work and the retained drain exist. Closed is published
only after every controller scope proves complete closure. Native-only
Maintenance drains KVM/hwmon but retains backend and its update jobs. Only
explicit resume from the retained owner publishes Active and reopens native
admission; it must never publish Closed while the backend tree remains alive.
`Resume::Retained` keeps ownership when closure/publication is incomplete or
uncertain; it never implicitly resumes. Drop merely releases the kernel lease,
preserving Active, Maintenance or Stopping.

| Acquired store observation | Native admission |
| --- | --- |
| No record, or valid Closed | Publish current-boot Active before launch |
| Current-boot Active, Maintenance or Stopping | Refuse: previous ownership is unresolved |
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

The lifecycle protocol listens at the protected journal directory's `control.sock`.
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

The daemon owns all three sibling roles and desired-role retries. `EnsureKvm`
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

`nanokvm-native-ctl` accepts only `activate-boot`, `boot-ready`, `status`, `running`,
`kvm-running`, `backend-running`, `ensure-kvm`, `ensure-hwmon`, `ensure-backend`,
`restart-backend`, `restart-backend-safe` and `shutdown`. Ensure waits for the
role's spawn/liveness acknowledgement (not service/hardware health). There is
deliberately no short-lived pause/resume command: exiting
would lose the retained maintenance connection. Shutdown reports completion only
after the proven drain/Closed state **and** positive exclusive-journal-lease
observation after the daemon's Stopped reply. A missing endpoint is sufficient
only when ready boot enrollment plus absent/Closed/prior-boot journal and the
exclusive lease independently prove no current managed native owner.
A CLI deadline or lost reply reports unknown completion without killing the
daemon. No valid production daemon invocation is used in host CLI tests.

Host private-directory fixtures cover real Unix socket exchange, fragmented I/O,
serial/replay rejection, actual peer UID mismatch, foreign-client denial,
maintenance EOF and durable reopening refusal, and safe endpoint cleanup.
A separate real subreaper fixture holds journal/listener/client descriptors while
launching and draining a daemonized tree to check descriptor isolation. These
tests do not execute production native roles or establish target runtime health.

## Backend restart and update exclusion

Backend start, restart and full shutdown require the fixed update-operation
exclusive lock followed by an enrolled configuration permit. Restart/shutdown
publish and sync Stopping **before** sending backend Stop; both permits remain
owned through the exact completion receipt, direct-owner exit and EOF. Restart
then optionally publishes the fixed MJPEG policy, spawns the replacement and
publishes Active before releasing admission. Safe-mode writes are fixed,
descriptor-relative, rootfs-only atomic file replacements; unsafe existing
objects are rejected before either destination is changed. They are not a
two-file crash-atomic transaction or a service-health receipt.

UpdateCoordinator checks the protected journal after acquiring that same
UpdateEX lock. Current-boot Stopping, corrupt/unsafe state, temporary publication
or recovery evidence reject new update admission. This durable fence prevents
controller death from releasing the kernel lock and admitting a new update
while a previously stopped backend tree is still being drained. Prior-boot
state proves old process lifetime only; independent raw/app recovery remains
required. Native-only Maintenance is deliberately not an UpdateEX fence: it
must be usable by a future issuer which already owns update admission, and it
neither stops the backend nor claims all-writer snapshot authority.

The backend owner independently waits for UpdateEX on controller loss. This
protects a live backend-owned update from a broker/transport failure, not from
backend death, kernel failure or a raw worker that has not retained independent
transaction authority. No signal is sent merely to turn a deadline into success.

The existing delayed app self-restart still owns its update lock while invoking
S95. The new full-shutdown admission therefore refuses that path. **This is an
open development integration gate, not acceptable final app-update behavior.**
Do not "fix" it by dropping the update lock before restart: protected retained
installer/broker handoff, journaled swap, health/retirement and rollback must be
implemented first. Directed helper upgrades, system watchdog, delayed requests,
AP/STA/ethernet descendant joining and complete authenticated raw/early apply
also remain open. No package/image from this intermediate state may be released.

## Fresh-boot init enrollment

The separate protected `/etc/kvm/native-runtime-boot` directory is root-owned
0700 on the rootfs. Its single-link root:root 0600 `state` is 80 bytes:
`NKBOOT01`, 36-byte epoch (all zero only for Factory), phase at byte44, three
zero reserved bytes and SHA-256 of the first48 bytes. The checksum detects
corruption; the protected producer/location is the authority, not this hash.
Unknown/unsafe records are preserved and rejected, not reset or upgraded.

| Entry state | Authorized transition |
| --- | --- |
| Factory, seeded only by offline full-image producer | Early S02 may publish Ready(current epoch) |
| Absent on a legacy install | Compile-bound backend bootstrap may publish Armed(current epoch), never Factory/Ready |
| Armed(current epoch) | No activation; reboot required even after manually rerunning S02 |
| Armed/Ready from an earlier epoch | Early S02 may publish Ready(current epoch) |
| Ready(current epoch) | Read-only current-backend restart; no legacy adoption |

Factory is **not** a mandatory predecessor for a legacy installation: the
intentional compatibility path is absent -> Armed -> new kernel boot -> Ready.
Only an offline image producer can grant immediate first-boot activation with
Factory. The app archive contains neither that record nor its directory.

S02 first runs the independent app recovery gate. Native activation then checks
all four installed critical consumer scripts against compile-bound SHA-256
digests with protected same-rootfs parents/regular single-link root-owned0755
files. Digests avoid embedding a second complete script copy in helpers. Main
arms **before** publishing scripts, retaining its exclusive boot guard through
publication; a partial repair cannot activate legacy processes in that same boot.
Already Ready main startup takes a shared guard after checking exact scripts.
The broker retains a shared guard through running, drain, maintenance and resume,
so a live broker prevents re-arming. Native journal Active/Maintenance/Stopping/recovery
still independently blocks startup: Ready never clears or overrides it.

State publication uses fresh exclusive random hidden names, file sync, rename
and directory sync. Hidden orphans are retained evidence and never selected.
An interrupted arm cannot certify readiness; retry only arms the current epoch.
No boot-ID, path or environment override exists in production.

Current S95 removes KVM/backend PID scanning/adoption/staging and hwmon
PID/killall fallbacks. It uses a fixed standalone broker, fixed ctl commands,
and verified three-scope shutdown before stopping the watchdog shells. A denied
shutdown preserves those watchdogs. Watchdog retries request admitted ensures
or backend restarts, never direct process launch, kill or broker replacement. The KVM
role runs the foreground vendor program directly from `/kvmapp/kvm_system` with
the same v0p7 loader/library path. That pathname/ABI and vendor-kernel behavior
still require target acceptance.

This is deliberately **not** all-writer quiescence: watchdog and delayed hwmon
request shells, STA/ethernet/AP state producers and trusted update issuer still
need a retained transaction-level join. Backend is a sibling, never a descendant
of the watchdog/native-maintenance tree; wrapping the serving backend and update
job in a native-only drain would kill that update. Do not do so or claim C1 closed. Directed
native executable upgrades, app journaled swap/health/rollback and complete
authenticated raw/early restore remain mandatory. DEVELOPMENT raw barrier must
not ship; no accepted image/release is produced by these host fixtures.

## Explicit native journal recovery

`nanokvm-native-recovery` accepts only `status`, `prepare` and `complete`, with
fixed protected paths and kernel boot identity. It is packaged but **not deployed
or automatically called by S95**. No force/reset/path/epoch override is
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

After a different boot, completion moves only `state`, `.state.next`,
`control.sock` and `app-install.sock` into `recovery/evidence/` with no-replace renames, or durably records
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

## Compile-bound native program delivery

Build all four static RV64 executables with
`server-rust/scripts/build-native-owner.sh`. The script rejects dynamic loaders,
shared-library dependencies and wrong ELF architecture. The linked backend build
first builds these in the separate static-helper target directory, then embeds
four independently framed payloads. Each frame has a fixed eight-byte domain,
exact length (at most 8 MiB), SHA-256 and static RV64 ELF checks:

| Program | Domain |
| --- | --- |
| `nanokvm-native-owner` | `NKNOWNR1` |
| `nanokvm-native-broker` | `NKNBRKR1` |
| `nanokvm-native-ctl` | `NKNCTL01` |
| `nanokvm-native-recovery` | `NKNREC01` |

`build.rs` requires all six valid helper inputs (including the existing SSH and
app-recovery bindings) for a linked RV64 build before writing any new binding
output. Host and static-helper builds may omit them and get empty bindings.
The linked backend checks the four native frames during startup. Build-input
environment variable names are only startup diagnostics, not runtime selectors.
This framing establishes consistency with a trusted backend, not a signature or
authority for an arbitrary supplied backend.

The packager extracts only embedded native bytes into `system/bin`, not a
separately selected helper source, and records their sizes/digests. Buildroot
installs root-owned mode-0755 copies in `/usr/libexec`, independently of the app
slot. Post-build restores both bundled and independent copies after generic ELF
fixups and verifies each against the final backend again. Both current ext-image
validation paths use `scripts/verify-native-runtime-rootfs.py`, which checks all
four domains, exact bytes, protected parents, root ownership, modes, single
links, file types and bounds. The direct vendor-image patcher also installs
these copies; its full pipeline still requires separate acceptance.

Host framing/CLI, package/post-build and disposable ext4 fixtures cover missing,
duplicate, substituted, corrupted and unsafe helper cases. These gates are not
app/full pipeline reproducibility, signature provenance, native target execution,
legacy bootstrap or first-restart evidence. Historical RC12 S95 bytes and the
private app archive's compatibility boot profile remain unchanged.

## Fixed-root file bootstrap

`update::native_bootstrap::prepare_boot_support` validates the complete app/native
payload set before mutation, then acquires one shared update lease. App recovery
and native bootstrap use that same admission. A non-cloneable `BootSupport`
retains it until main finishes publishing the compile-bound consumer scripts.
If preparation fails, main withholds those scripts while preserving management.

Native canonical files must match exact embedded bytes, root UID/GID, mode 0755,
single-link regular-file identity and the protected same-rootfs parent. Existing
parents forbid shared writes and all special bits; symlink/mount crossings are
rejected. Parent group ownership supplies no authority. All existing roles are
checked before any missing role is staged. Missing files are allowed only with
no app-slot transaction; an existing transaction allows exact full-family
verification only. Unknown or older native binaries are never replaced. A
directed old-native upgrade still needs retained-owner and journal compatibility
review, not a version string or a matching runtime manifest.

Missing files are written to fresh exclusive random rootfs names, chmodded and
file-synced, then published with NOREPLACE and directory sync. Interruption may
leave an exact subset and staged evidence. Retry validates existing members and
finishes missing names; the complete family is rechecked before success. Staged
evidence is not a fallback executable and is not automatically deleted. The app
install prerequisite separately requires the complete exact family under its
already-owned update admission; it never repairs missing support.

Host tests cover every partial-family mask and journal phase, foreign late
members, unsafe file/parent metadata, aliases and FIFO input. The explicit
`server-rust/scripts/test-native-bootstrap-root.sh` gate runs real fixed-root
entries in disposable namespace/chroot children with actual embedded RV64 bytes
as data. It checks app/native prerequisite composition, busy admission, corrupt
decoded state and SIGKILL at staging/publication/returned-guard boundaries.
No helper or service is executed by these fixtures. They are not S95/legacy
process transition, target rootfs, native quiescence or update acceptance.

The backend's new frozen trial entry checks the existing app/native family and
critical scripts without acquiring the app store or update/writer admission
already owned by its parent. The bound-root test retains the real exclusion
inodes, including an exclusive app-store lock, while verifying these exact
embedded bytes. This is read-only support inspection, not a new scope launch:
the owner still launches only its existing three normal roles. Broker-to-owner
trial startup, native-service health, explicit trial stop/join, commit and
rollback after trial are not yet connected. See
[frozen startup](security-app-slot-recovery.md#frozen-trial-startup-backend-entry-not-yet-broker-launch).

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
