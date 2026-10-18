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

Build the static RV64 component with
`server-rust/scripts/build-native-owner.sh`. The script rejects dynamic loaders,
shared-library dependencies and wrong ELF architecture. This is not app/full
pipeline reproducibility or target execution evidence. The ordinary package
builder intentionally does not include this unused component yet.

Remaining work is a production lifecycle broker/retained owner: close admission
to respawners, stop/join watchdog work, then stop/join native services and settle
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
