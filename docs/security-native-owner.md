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
is compiled, but has **no production caller or packaging/S95 switch yet**.

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

## Durable native broker admission component

`native_owner::broker::Broker` now combines the sibling group with a protected
singleton journal. It is a library component with **no production caller or
S95/watchdog daemon yet**, not a replacement for the separate raw restore ticket.

The fixed store is `/etc/kvm/native-runtime-owner`: root-owned mode 0700 on the
same rootfs, opened descriptor-relatively with no symlinks, magic links or mount
crossing. A nonblocking exclusive flock uses the stable directory inode, which
is never unlinked. State is one single-link, root-owned mode-0600, fixed 80-byte
record. Its SHA-256 detects corruption, not authenticity; protected location is
the trust boundary. It contains only format, boot epoch and Active/Closed phase,
not credentials, process-number authority or raw-update authorization.
The closed restore allowlist does not preserve/import/delete these runtime
authority members; capture and forged write/absent-archive tests cover both names.

Before the first possible native launch, Active is written to an exclusive
temporary member, file-synced, renamed, and directory-synced. The journal lease
stays owned while native work and the retained drain exist. Closed is published
only after every controller scope proves complete closure. `Resume::Retained`
keeps ownership when closure/publication is incomplete or uncertain; it never
implicitly resumes. Drop merely releases the kernel lease, preserving Active.

| Acquired store observation | Native admission |
| --- | --- |
| No record, or valid Closed | Publish current-boot Active before launch |
| Current-boot Active | Refuse: previous ownership is unresolved |
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
Recovery from an incomplete record and supported operator recovery remain open;
this fail-closed prototype must not be enabled in S95 without that lifecycle.

Host verification injects I/O failures and kills real journal-owner subprocesses
at six publication boundaries. Broker tests check pre-launch intent, retained
drain, missing receipts and cleanup-publication failure, plus a real dedicated
subreaper with a daemonized native fixture while the journal descriptor is held.
These are not power-cut tests, vendor runtime evidence or device acceptance.

Build the static RV64 component with
`server-rust/scripts/build-native-owner.sh`. The script rejects dynamic loaders,
shared-library dependencies and wrong ELF architecture. This is not app/full
pipeline reproducibility or target execution evidence. The ordinary package
builder intentionally does not include this unused component yet.

Remaining work is a production lifecycle broker/retained daemon: integrate the
durable component with authenticated IPC and supported recovery; close
admission to respawners, stop/join watchdog work, then stop/join native services and settle
pending AP attempts. Do not naively nest an independent service owner below a
watchdog subreaper: that creates ownership/teardown coupling, not independent
service lifetimes. Broker commands, app restart and raw handoff must explicitly
preserve the correct owners and immutable runtime provenance.

The integration must record unresolved/crashed ownership outside mutable p3 and
fail before partition writes. A dead owner or EOF without a complete receipt
cannot establish that its descendants stopped. Parent/controller failure, owner
SIGKILL/OOM, supported recovery, exact vendor program behavior and physical
acceptance remain open. Cgroups/PID namespaces are not assumed or enabled.

C1, complete service closure, canonical multi-file settings capture, retained
raw writer/ticket/early restore and production capture remain open. See
[state writers](security-state-writers.md) and
[update ownership](security-update-ownership.md).
