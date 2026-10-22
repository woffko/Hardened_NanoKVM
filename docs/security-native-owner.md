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
all-owned-scope drain before slot publication, including an enrolled optional
PicoClaw scope. It retains that fence through explicit
old-slot rollback and offers a typed backend-only frozen trial transition.
The daemon now invokes it for a validated prepared offer on its separate
app-install endpoint and now drives its frozen trial, commit and failure/cancel
stop-join transitions. Successful live terminal archival now preserves the
receipt/inactive slot and permits a subsequent transaction; archival failure
retains the owner and exclusions. Root has an explicit live-terminal archival
retry, which cannot reset later ownership uncertainty. The ordinary API remains
legacy; nonterminal/owner-loss and fresh-boot completion, bounded retention,
daemon-to-real-backend/runtime and device acceptance remain required.

## Implemented boundary

Before launch the owner requires an anonymous Unix socketpair, exactly one
thread, no pre-existing children, default SIGCHLD disposition, and no extra
inherited descriptors. Its private control duplicate is CLOEXEC and child stdin
is `/dev/null` for normal roles. Production entry additionally requires root and
the socket peer credentials of its direct parent. Four normal fixed roles are
accepted: `kvm-system`, `hwmon`, `backend` and optional `picoclaw`. The first three
use explicit vendor loaders/library paths. PicoClaw selects only
`/usr/bin/picoclaw gateway`; the separate fixed `picoclaw-onboard` variant runs
`/usr/bin/picoclaw onboard` against a fresh derived scratch home. Neither is
automatically enabled. The fixed `backend-trial` variant adds only `--app-trial` and a separately
created transaction-bound startup channel after the inherited-FD audit.
Backend executes `/kvmapp/server/NanoKVM-Server` directly; no mutable `/tmp`
staging copy or PID-file adoption remains in the current S95 launcher.
There is no generic shell/program/path or environment selector or fixture fallback.
The one named `PICOCLAW_HOME` input is resolved to an absolute pathname for the
backend/trial and Pico command environments; it does not authorize filesystem
access, pair recovery, a configuration generation or a service transition.

The owner enables the kernel child-subreaper property and checks actual pidfd /
`waitid(P_PIDFD)` support before starting native work. Subreaper adoption survives
ordinary daemonization, including `setsid`; it does not itself stop a process.
See [Linux subreaper semantics](https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html)
and [pidfd identity/lifetime](https://man7.org/linux/man-pages/man2/pidfd_open.2.html).

Explicit Stop starts TERM, followed by KILL after two seconds. Native KVM/hwmon/PicoClaw
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

`native_owner::controller::Group` has four fixed sibling slots, including the
optional PicoClaw role. It owns those sibling owner processes, never installs a
subreaper in the async backend and has no
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
Stop on every non-backend sibling and refuses new starts/resume. It does not stop
a healthy backend merely because KVM/hwmon/PicoClaw ownership is uncertain. Backend
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

### Optional PicoClaw scope and partial service integration

Native-only maintenance stops and joins KVM, hwmon and an enrolled PicoClaw scope,
retaining the backend. Full shutdown/install joins every enrolled slot. The
backend-only app trial rejects any non-backend slot that is neither absent nor
closed. Pico ownership uncertainty latches broker admission even though the
existing fixed control reply still has only the KVM/hwmon status bytes. The
native lifecycle compatibility epoch is now 8; epoch-1 through epoch-7 transitions
are refused, and `support_transition=0` still refuses even a matching epoch-8 live transition.
The separate boot receipt now has a generation-bound v2 format; the native
Active/Maintenance/Stopping journal is unchanged. No automatic legacy adoption
was introduced.

Host fixtures include a SIGSTOP-held Pico owner, a daemonized setsid descendant
which ignores TERM, maintenance retaining a real backend tree, hidden-role
receipt loss, and four-role app install/trial/rollback. These establish the
controller/retained-session behavior, not execution or health of the installed
PicoClaw program.

Ordinary API and current S96 start/stop/onboard now use fixed broker operations rather
than direct gateway launch, pidof or process-name killing. This is partial
service integration, not adoption of an already running legacy process or C1/H2
closure. Interrupted onboarding recovery, install/uninstall and profile/workspace writers still require
complete ownership/enrollment, runtime-intent handoff and target acceptance.
Uninstall now refuses deletion after an unverified Stop, but this alone is not
serialized stopped ownership through deletion or protection against all writers.
Preserve the separate enforceable local-tool privilege boundary and target
GUI/HID autonomy.
The broker now freezes its lexical home before opening the native journal and
uses the same absolute selection for backend, trial and optional Pico launches
through drain/resume/rollback. A malformed explicit home refuses broker startup
before any native intent or launch; it is not silently replaced by the root
default. This is a deliberately fail-closed launch configuration, not Pico-only
error isolation or validation of filesystem trust. Independent legacy launchers
are not automatically migrated by this in-memory binding.

### Optional S96 file publication during legacy bootstrap

`prepare_boot_support` now retains UpdateEX, then a configuration-writer permit,
then the boot permit until the caller finishes mandatory script publication.
Configuration contention refuses before publishing any support helper. Release
order is boot, configuration, update; the later startup trust/configuration
reload still runs only after these permits are dropped.

An absent `S96picoclaw` stays absent. An exact current protected script is synced
without changing its inode. A differing installed script is replaceable only
with a live exclusive boot permit whose canonical receipt is Armed for this
kernel boot, no app-slot transaction, and an exact reviewed predecessor identity:
RC12 source at `387793ab` (3316 bytes, SHA-256
`499258cb3d84aad2ddf179b7d5f6e3e82abb7db889f3db22b8ae3a9f0ae88272`),
or development source at `4606dfb` (3313 bytes, SHA-256
`3a2bff86d284bf6f38666db71133941b22e46f04f8068c15f1fd586b9d0f8153`).
Unknown/custom content, unsafe metadata, symlinks, hardlinks and non-regular
objects are refused without overwriting them. A shared Ready observation is
never replacement authority.

Publication stages immutable compiled bytes under an exclusive random name,
syncs the file, rechecks the old canonical inode, exchanges names atomically,
syncs the parent and verifies both installed and retained old images. The old
inode remains evidence, not a fallback executable; orphan staging evidence is
not consumed or deleted on retry. This is filesystem publication, not stopping,
adopting or restarting a running legacy gateway. It cannot grant same-boot
Ready, does not add a fifth framed support-catalog entry, and does not enable
the still-unsupported live helper/support transaction. Current S96/API route
start/stop/onboard through the broker only with current enrolled support; all Pico
writers, complete legacy/helper migration, pending-pair capture settlement and
H2 remain required.

### Fixed optional-scope service operations

The NKC2/NKR2 frames remain 48 bytes. Each operation below carries the full
32-byte home fingerprint in its own request; a prior home query grants nothing.
The ctl accepts no alternate executable, pathname, environment map or arguments.
All six ctl service operations require and retain a current fresh-boot receipt
for this executing client's compiled consumer profile, before broker contact.

| Operation | Opcode | Fixed ctl command | Meaning |
| --- | --- | --- | --- |
| EnsurePicoclaw | 14 | ensure-picoclaw | Admit one exact owned launch or verify its unchanged pair generation |
| PicoclawRunning | 15 | picoclaw-running | Observe owned-scope readiness, not gateway/application health |
| StopPicoclaw | 16 | stop-picoclaw | Admit Stop, then ctl waits for the separate Stopped query |
| PicoclawStopped | 17 | picoclaw-stopped | Observe receipt + owner reap + EOF, or absence of an enrolled scope |
| OnboardPicoclaw | 18 | onboard-picoclaw | Admit a fixed fresh-home one-shot or preserve an existing valid pair unchanged |
| PicoclawOnboardComplete | 19 | picoclaw-onboard-complete | Observe the last one-shot's successful closure and checked import, not upstream gateway health |

Home mismatch refuses before any lifecycle tick. Read-only queries do not launch
pending wanted work. Exact serial+frame replay returns the prior response and
cannot start/stop a later generation. Non-home operations still require a zero
reserved tail, and all replies retain the zero tail and existing two-role view.

Ensure retains UpdateEX then Config through the coherent generation check and
fixed spawn. An absent/closed scope requires app-slot admission before stopped
pair recovery. The generation hashes exact bounded JSON/security bytes, lengths
and explicit security absence; it is in-memory only and must not be logged.
Running generation mismatch refuses without adoption or an implicit restart.
Generic broker role startup refuses Pico, so it cannot skip this operation.
Readiness means native owner startup, not a successful upstream gateway session.

Rust config readers may expose a coherent committed-intent view from a pending
pair journal. Native readers consume canonical files instead: their generation
comparison refuses any pending journal without mutation. Only stopped launch
preparation under Config may settle that journal, then fingerprint installed
bytes. A crash test verifies the actual mixed on-disk intermediate state.

Stop acquires only UpdateEX: an API caller already holding Config must not
self-conflict on that same permit. The engine retains Update through caller
disconnect and polls the existing owned Pico cell until its full closure proof.
KVM/hwmon/backend scopes continue running. Pending Stop blocks maintenance,
backend restart, full shutdown and app-install admission; uncertainty pins the
same guard even after a childless protocol fixture has exited. The global Active
journal stays conservative; Pico Stop is not whole-broker Stopping or proof that
all external/configuration writers are gone. No PID lookup, killall, journal
reset, owner adoption or automatic restart is offered.

These commands concern the enrolled optional scope only. They do not prove an
independently launched legacy gateway is stopped. API/S96 migration must first
exclude those legacy launchers and bind every writer, including gateway default
refresh, interrupted onboarding recovery, binary install/uninstall and profile/workspace changes.

### Ordinary API/S96 control routing

API start takes nonblocking Update admission before queuing blocking preflight
work (contenders cannot grow a helper-hashing queue), checks this backend's
exact installed native helpers and obtains its compiled current fresh-boot proof
before preparing defaults. It releases Update before submitting Ensure (the broker
acquires its own Update/Config), but the command owner retains the shared boot
proof through capture/cancellation/direct-child reap. Stop uses the same fixed
helper proof and no app-script selection, Config read or process-name fallback.
A helper error, timeout or lost reply is not Stopped. The existing broker retains
its own Stop exclusion/receipt/reap/EOF responsibility after the client dies.

S96 first calls the new `picoclaw-control-ready` entrypoint, then the actual
ensure/stop/onboard operation. Older clients that knew the original service verbs reject
this new entrypoint instead of acknowledging an empty owned scope. The new probe
checks/retains the compiled boot profile and uses the existing full-home-bound
Running-owner query; it grants no lease to the later connection. Every actual
service operation independently binds the home and retains the boot profile.
S96 no longer changes cwd, creates the home, opens a gateway log or launches the
runtime for start/stop/onboard. No shell workspace copy/removal remains.
Missing/mismatched helpers refuse without fallback. Restart stops before start
and propagates a failed/unverified Stop; extra arguments refuse without control.

A legacy installation with missing/different helpers or an Armed/old-generation
receipt can retain diagnostic web access, but new API control refuses before
default publication. Publishing a script is not enrollment; a supported helper
transition and real fresh boot are still required. Do not use this refusal as a
claim that the old gateway was stopped or that in-place migration is complete.
Current source routing is not installed-device or all-writer acceptance.

`make test-picoclaw-native-routing` checks fixed routing and error propagation
using synthetic ctl responses; historical launcher bodies are never executed.
This complements real native ownership/root fixtures, not target acceptance.

### Owned first-run onboarding

Onboard shares the optional Pico cell, so a live gateway, pending Stop, another
onboarding task or admission contention refuses before starting a writer. The
broker retains UpdateEX then Config, independent of the requesting connection,
through receipt, owner reap, EOF and checked output import. A 60-second deadline
requests owned Stop; neither timeout nor Stop counts as successful onboarding.
Missing/invalid closure pins both admissions and uncertainty. Pending onboarding
also blocks app install, maintenance, backend restart and full shutdown.

The fixed owner launches against `<effective-home>/.nanokvm-onboard`, created
exclusively on the checked rootfs. HOME, PICOCLAW_HOME, PICOCLAW_CONFIG and cwd
point into that scratch; no credentials/environment map is inherited. Existing
installed config is a no-op, not upstream re-onboarding. The upstream v0.2.8
source overwrites workspace templates, so it never receives the installed home.
See [checked import and its remaining recovery limits](security-picoclaw-config-io.md#owned-first-run-import).
These are host-tested source paths, not proof that the separately supplied
optional binary matches the inspected upstream source, nor H2 isolation.

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
Maintenance drains KVM/hwmon and any enrolled Pico scope but retains backend and
its update jobs. Only
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

Both ends verify kernel `SO_PEERCRED` root UID. Requests and replies have fixed
48-byte `NKC2`/`NKR2` frames with a closed operation set, reserved-byte validation
and connection-local serials in bytes8..16. The last32 bytes must be zero except
for the fixed `CheckPicoclawHome` request, which carries the full domain-separated
SHA-256 fingerprint of the selected absolute UTF-8 path. Replies always require
that reserved tail to be zero. Old version-1 or malformed frames are rejected;
there is no protocol fallback or shortening of a fingerprint to a status byte.
At most 16 clients are retained; I/O is nonblocking with bounded work per loop.
An exact duplicate of the last request returns its cached response without
executing again; conflicting replay, gaps and invalid frames close the connection.
There is no generic shell, path, environment, raw writer or settings import opcode.
Root peer identity is **not** executable attestation or a hostile-root sandbox.
The later unprivileged picoclaw/admin capability split remains separate work.

`nanokvm-native-ctl picoclaw-home-check` sends only that32-byte fingerprint and
prints the caller's already-selected absolute path on a matching Running reply.
The query cannot select/change a home, create state, onboard or launch a service;
it performs no extra lifecycle tick even when the broker has pending wanted
work. Mismatch returns Invalid, non-Running ownership Busy/Uncertain. This is a
point-in-time comparison, not a lease, a config-file generation, filesystem
validation or permission for a later start/capture/reconnect. An exact cached
reply can describe the earlier observation. Future Pico commands must bind their
own request to the same live owner's home and retained writer/service admission,
not treat this short-lived ctl query as a transferable capability.

The daemon requests KVM/hwmon/backend roles and retains any explicitly enrolled
optional Pico scope. Current API/S96 route Pico ensure/stop with the separate
fresh-boot/current-helper gates described above. `EnsureKvm`
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
`restart-backend`, `restart-backend-safe`, `retry-app-retirement` and `shutdown`.
Ensure waits for the role's spawn/liveness acknowledgement (not service/hardware
health). There is deliberately no short-lived pause/resume command: exiting
would lose the retained maintenance connection. Shutdown reports completion only
after the proven drain/Closed state **and** positive exclusive-journal-lease
observation after the daemon's Stopped reply. A missing endpoint is sufficient
only when ready boot enrollment plus absent/Closed/prior-boot journal and the
exclusive lease independently prove no current managed native owner.
A CLI deadline or lost reply reports unknown completion without killing the
daemon. No valid production daemon invocation is used in host CLI tests.

`RetryAppRetirement` addresses only a retained live terminal app owner. It
repeats exact archival/sync/release, never installation, journal-only recovery,
rollback, collision deletion or forced uncertainty clearing. Partial frames have
no effect and exact replay uses the same cached-reply rule. It preserves the
group's latched uncertainty, including owner loss while waiting for I/O repair.
Its Ok/Running is release/admission, not service health. See
[live-terminal retry](security-app-slot-recovery.md#explicit-live-terminal-archival-retry).

Terminal filesystem settlement runs in one retained worker, not in the broker's
supervision/request loop. The broker keeps the native group and polls ownership
while the worker borrows the accepted install. The main owner retains the
update/store/writer exclusions through spawn failure, caught unwind, caller EOF
and uncertain I/O. The release profile uses panic=abort: a production panic
terminates the daemon and requires durable recovery, not a live retry. A failed
attempt requires explicit retry; an in-flight one
cannot be replaced or cancelled. Retry's Ok/Installing acknowledges only a new
attempt; the CLI observes until Running and treats uncertainty/deadline as
non-success. The worker is joined before its successful result can release
admission, and teardown joins rather than detaches it. Kernel-blocked I/O can
still delay teardown. This does not move every other install stage off-loop or
establish whole-install latency/target acceptance.

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
0700 on the rootfs. Its single-link root:root 0600 `state` is 112 bytes:
`NKBOOT02`, 36-byte epoch (all zero only for Factory), phase at byte44, optional
S96 presence at byte45, two zero reserved bytes, a 32-byte consumer generation
at bytes48..80 and SHA-256 of the first80 bytes. Ready binds the full generation
and exact optional presence; Factory/Armed must have an all-zero profile. The
generation hashes a fixed domain plus the five compile-bound script digests,
including the trusted optional S96 source even when it is not installed.
The checksum detects corruption; the protected producer/location is the
authority, not this hash. Unknown/unsafe records, including historical 80-byte
`NKBOOT01`, are preserved
and rejected, not reset or promoted. Old development-format installations need
an explicit compatible migration or trusted reflash; live support transition
is not implemented. Historical images keep their own historical verifiers.

| Entry state | Authorized transition |
| --- | --- |
| Factory, seeded only by offline full-image producer | Early S02 may publish Ready(current epoch) |
| Absent on a legacy install | Compile-bound backend bootstrap may publish Armed(current epoch), never Factory/Ready |
| Armed(current epoch) | No activation; reboot required even after manually rerunning S02 |
| Armed/Ready from an earlier epoch | Early S02 may publish Ready(current epoch) |
| Ready(current epoch), exact generation/presence | Read-only current-backend restart; no legacy adoption |
| Ready(current epoch), safe but changed optional presence/generation | Bootstrap may only arm this epoch; direct early activation refuses; fresh boot required |
| Malformed/foreign/unsafe installed script | Refuse without replacing the script or authorizing Ready |

Factory is **not** a mandatory predecessor for a legacy installation: the
intentional compatibility path is absent -> Armed -> new kernel boot -> Ready.
Only an offline image producer can grant immediate first-boot activation with
Factory. The app archive contains neither that record nor its directory.

S02 first runs the independent app recovery gate. Native activation then checks
all four installed critical consumer scripts against compile-bound SHA-256
digests with protected same-rootfs parents/regular single-link root-owned0755
files. Optional `/etc/init.d/S96picoclaw` must be absent or have the exact trusted
source bytes and the same safe metadata. The installed name is rechecked after
hashing; absence is rechecked after the scan. This is a protected-input snapshot,
not a sandbox against arbitrary root writers. Enrolled installers still need
the retained boot/native/writer barriers before changing these inputs.
Digests avoid embedding a second complete script copy in helpers. Build-time
validation reads all five trusted sources before publishing any generated
binding; optional deployment does not permit missing/empty/oversize source.
Main arms **before** publishing scripts, retaining its exclusive boot guard through
publication; a partial repair cannot activate legacy processes in that same boot.
Already Ready main startup takes a shared guard after checking exact scripts.
The broker retains a shared guard through running, drain, maintenance and resume,
so a live broker prevents re-arming. Native journal Active/Maintenance/Stopping/recovery
still independently blocks startup: Ready never clears or overrides it.

S96 is still optional and is not auto-installed by this check. Its current
start/stop/onboard paths are fixed broker operations; older installed launchers
are not adopted by that routing.
Exact provenance/presence does not adopt that process, establish configuration
generation or authorize Pico service activation/capture. Fixed native routing,
all writer closure and a supported optional-script/helper migration remain
required. The four framed critical-script support entries do not silently gain
an optional fifth executable transition entry.

State publication uses fresh exclusive random hidden names, file sync, rename
and directory sync. Hidden orphans are retained evidence and never selected.
An interrupted arm cannot certify readiness; retry only arms the current epoch.
No boot-ID, path or environment override exists in production.

Current S95 removes KVM/backend PID scanning/adoption/staging and hwmon
PID/killall fallbacks. It uses a fixed standalone broker, fixed ctl commands,
and verified all-owned-scope shutdown before stopping the watchdog shells. A denied
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

## Candidate helper-family consistency (migration prerequisite)

The opaque app-candidate factory now checks all five helper bindings before it
can return a candidate for durable issuance: app recovery, native owner, broker,
client and native recovery. Each role needs one valid SHA-256/static-RV64 frame;
valid duplicates and cross-role nested/overlapping frames are refused. Invalid
literal markers are not helpers, but count against the per-role scan limit.
Backend size, role sizes, marker count and cumulative hash work are bounded.
The inspector uses fixed-size buffers and positional reads, not a whole-backend
allocation or a shared-cursor seek.

Both bundled Rust backend copies must be byte-identical, and each fixed
`system/bin` helper must match the selected frame's size/digest. Required files
are inspected with O_PATH before a nonblocking data open; same-rootfs, owner,
single-link regular-file, safe-mode and no-alias checks apply. Required parent
directories are checked too. A failure does not install, chmod-repair or start
anything. This preflight happens after archive provenance/fingerprint and
version checks and before the opaque candidate is returned, not after live
app publication. Administrative offline import still requires the administrator's
external checksum/provenance verification; this check does not invent a release
signature for it.

`update::helper_family::inspect` is only a read-only consistency diagnostic. Its
FD is not an immutable-source or execution capability. The production factory
owns fresh protected private extraction and must keep it stable; a malicious
local root/cooperating writer is not excluded by a SHA-256 scan or file descriptor.
The test-only image-runtime probe can compare these diagnostics to real linked
artifact bytes, but cannot issue an install or supply candidate authority.

This is **not helper-family migration**. Existing native bootstrap still refuses
different installed bytes, and frozen trial still requires exact installed
app/native helpers and critical scripts. The next retained-owner transition
must keep the exact predecessor family and durable interrupted-swap evidence,
check journal/wire compatibility, restore that family on uncommitted rollback,
and make startup recovery settle the same transaction before normal consumers.
App-slot rollback alone currently restores only the app tree. Do not activate
the ordinary POST path by replacing helpers in place or weakening trial checks.

The same transition must account for all four compile-bound boot scripts, not
just the five executables: frozen trial checks both. The app-only archive
deliberately carries historical S95 and omits S02/S30eth/S30wifi so old RC12 does
not publish new gates before bootstrap. Those archive-profile bytes are NOT the
target's canonical bootstrap payload. Compatible, authenticated delivery and
durable predecessor recovery of the canonical scripts must be designed with
helper migration; do not silently turn the legacy archive profile into an
in-place script-upgrade source.

The backend build now frames the same canonical script bytes with fixed role,
length and SHA-256 headers. `BOOT_SCRIPTS` references their payload suffixes;
there is no second script body or mutable support directory. The backend retains
the complete frames, while the app archive keeps its historical boot profile.

`update::boot_script_catalog::inspect` is another read-only diagnostic, not an
installer. It first checks the complete helper family, excludes frames inside
those helper images, and requires four unique nonoverlapping top-level script
frames. Script bodies are capped at 64 KiB, markers and cumulative hashing are
bounded, and reads use fixed buffers without moving the shared cursor. Frame
checks do not authenticate an outer backend or make its contents immutable.

Actual linked-byte and private archive-preflight tests cover this representation;
they do not establish a helper ABI, retained support swap or recovery capability.
No production publisher consumes this catalog yet. The running broker's own
compatibility must be checked as well: app update retains that process, so the
new broker file on disk does not identify its current implementation. These
requirements remain prerequisites to enabling the canonical update path.

The build also emits a separate 128-byte `support_abi` declaration for the
backend and each of the five helpers. Roles and format/group epochs are explicit;
reserved fields and a domain-separated SHA-256 detect inconsistent framing.
These declarations are not signatures, executable attestations or privileges.
The current support-transition epoch is zero: matching zero never permits an
exchange of independently installed helpers or scripts.

`support_abi_catalog` checks one declaration in each verified helper image and
one outside helper/script frames for the backend. It uses bounded positional
reads, rejects duplicate/cross-role/cross-boundary declarations, and preserves
unknown group versions for explicit compatibility refusal. Checksum-valid
unknown formats or reserved fields cannot be skipped for a later good frame.
Only declarations wholly enclosed in a script frame are treated as opaque
script data; a checksummed declaration crossing its edge is rejected.
Neither a file descriptor nor a parsed catalog establishes immutable provenance.

The retained broker's in-process compatibility check uses its own compiled declaration,
not the successor broker executable on disk or a caller-supplied live version.
There is no separate ABI-query operation on the native control wire. The
read-only method is a prerequisite, not a `ClosedRuntime` capability.
The complete nine-entry protocol and its acceptance remain required before
enabling canonical publication; the source boundaries below are not activation.

The initial nine-file preparation core lives inside the retained app-slot owner.
`Session::start_support` first requires the same native drain. It transfers the
accepted install to a retained worker owner while keeping Drain/journal/enrollment
in the broker. Only the private transaction-bound closure proof reaches the
fixed support operation; the worker cannot resume or supervise native processes.
It pins both recorded app roots and the fixed support parents, checks both
catalogs against the executing build, and allocates all successors anonymously
before publishing a bounded, transaction-bound plan in the private rootfs
`/etc/kvm/application-support` store. Named links must match the recorded inodes;
all nine links precede `Ready`. This store is separate from app receipts and is
not an importable restore/preserve tree. Capacity checks preserve recovery
headroom but do not constitute a filesystem reservation.

The retained guard now also exchanges the nine exact inode pairs and restores
an uncommitted predecessor. Each exchange syncs both affected parents; retry
checks actual placement rather than blindly exchanging again. App publication
and frozen-trial admission require the complete successor family. Rollback
restores old support before the old app, while canonical `Committed` never
selects the predecessor on an unknown acknowledgement.

Terminal cleanup runs under the same checked terminal owner before app archival
or freeze release. It records the canonical cleanup direction, removes only
exact inactive members, syncs each unlink and removes the plan last. A supported
`plan-next` edge must match the same transaction, parents and objects; torn or
foreign alternatives refuse. Early NoTransaction and terminal deferral paths
require a clear support store instead of bypassing pending evidence.

The current transition epoch is still zero, so the production entry refuses
before creating that store. Stopped/prior-boot recovery now reconciles support
before app slots under the same `FencedAppRecovery`, retained update/store/writer
exclusions and durable recovery intent. Canonical `Committed` selects successor
support; other supported app states restore predecessor. Terminal support cleanup
precedes app archival, native `Closed` and intent removal. An empty support store
is synced and rechecked without requiring an already archived `current` name.

The retained Engine orchestrates preparation/exchange before app publication.
One fixed I/O worker executes that filesystem work while the broker continues
polling native closure and serving control requests. The accepted store/update/
writer exclusions stay with the retained owner through caller loss, worker
failure and unknown I/O. The worker guard borrows the accepted install only
inside its stack; there is no self-reference across daemon ticks. Conversion
back to Session requires a finished/joined worker, unique accepted ownership
and fresh main-thread closure checks. Native uncertainty remains distinct from
a filesystem failure and cannot be cleared by a queued cancellation.

After support exchange, app publication uses the same retained closed-runtime
supervision with a distinct fixed worker operation. It obtains a fresh closure
proof before starting and requires the exact `Published` filesystem result.
Preservation, canonical layout checks, journal records, renames and fsyncs are
unchanged. Native Drain/journal/enrollment stay on the broker. A support result
can advance only to SupportReady; a publication result only to Published, and
neither starts trial until the worker is joined and native closure is rechecked.

Cancel during support or publication I/O acknowledges a queued rollback, not
completed cancellation. It never starts a concurrent filesystem operation:
after join, rollback must obtain a fresh closed-runtime proof and validate the
actual support/app layout. Native uncertainty prevents that transition. Observation,
reconnect and path repair never retry failed preparation or publication. Spawn
failure, caught unwind and panic-after-I/O fixtures retain the same accepted
owner; production panic=abort still requires durable process recovery. Teardown
joins before releasing admission, so kernel-blocked I/O can delay teardown.

With support-transition epoch0 the production Engine still refuses before
support or app publication. Durable commit and rollback now use distinct fixed,
joined workers; rollback includes both support/app restoration and native-journal
resume in the same result boundary. The broker retains the same Drain and checks
closure before submission and after completion; it cannot resume or retire a
failed, panicked or uncertain result. Cancellation during rollback does not start
another operation or report completed cancellation. Teardown joins filesystem
work before releasing singleton and accepted update/store/writer admission.
These changes do not enable the ordinary update API or establish all-writer
quiescence. Other synchronous transitions and real native/runtime behavior still
require acceptance; no whole-install hard latency or target acceptance is claimed.

Host tests compose real retained `Session` drain and terminal owners with
synthetic protected payloads and child protocol probes. They cover successful
commit, failed-trial rollback, preparation abort, lost commit acknowledgement,
missing closure receipt and unknown support evidence. The private test seam
uses the real session's closure token and bypasses only transition0; it is absent
from production. Separate fixed-root fixtures cover process kills and injected
I/O failures through reconciliation, cleanup and archival. Their synthetic
prior-epoch record is not a physical reboot or same-boot closure permission.

Bounded child-private tmpfs tests also cover byte/inode reserve refusal, actual
post-preflight `O_TMPFILE`/payload-write ENOSPC, readonly preparation/settlement
and exact retained-owner retry. Separate success checkpoints prove that the
intended kernel operation did not complete; an arbitrary later error is not
accepted. Host-side evidence and the parent mountpoint remain unchanged.

Engine fixtures now carry synthetic complete predecessor/successor families,
including successive installs and production fixed-root endpoint delivery. Their
private opt-in permits only the unsupported-transition result; missing or
incompatible declarations still fail. They check refusal of the executing
epoch0, absent/matching-unknown contracts, every unknown live member, all-three
scope closure before exchange, cancellation before app publication and foreign
support evidence after exchange. Commit acknowledgement, failed-trial rollback
and missing-closure cases also retain/check the real nine-file journal. These
payloads and child probes are not authenticated release/device acceptance.

Real native/vendor runtime, ext4/vendor-media allocation, legacy first-bridge/
restart, ordinary API activation and device migration remain incomplete. These
host fixtures are not physical boot, hardware power-loss or release acceptance.

## Frozen trial and recovery integration

The backend's new frozen trial entry checks the existing app/native family and
critical scripts without acquiring the app store or update/writer admission
already owned by its parent. The bound-root test retains the real exclusion
inodes, including an exclusive app-store lock, while verifying these exact
embedded bytes. This read-only inspection is separate from the new typed broker
trial transition and fixed owner relay. The policy keeps KVM-system/hwmon closed
until the post-commit writer freeze ends, and requires explicit stop/join before
uncommitted rollback. Separate host tests cover protocol readiness/commit and
failure closure, not actual native-service health. The Engine and independent
daemon now drive those transitions with host protocol probes, including
frontend/observer loss, retained failed commit and post-freeze native restart.
Exact terminal archival and per-ID observation are host-tested, including
retained release failure and sequential app transactions. Direct early app
recovery also checks the durable same-boot native Stop fence after acquiring
UpdateEX, so installer death cannot bypass that fence merely by releasing a lock.
Stopped/prior-boot app recovery now retains its own singleton boundary: canonical
Closed in this boot or a valid previous kernel epoch, then durable current-boot
Stopping before app changes, exact app recovery/archival, and Closed only after
durability. A protected transaction/inode receipt also covers current already
archived before helper death. Missing native state and same-boot unresolved
owners are not adopted. The lease remains held through app receipt cleanup;
Drop never publishes Closed. This does not expose Group launch or raw authority.
Real backend/runtime integration, complete I/O/physical fresh-boot retirement
and device acceptance remain open. See
[trial policy](security-app-slot-recovery.md#broker-owned-trial-policy).

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
