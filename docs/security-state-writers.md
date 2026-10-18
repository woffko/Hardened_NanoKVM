# State writers before raw capture

The [machine-readable inventory](security-state-writers.json) classifies every
explicit path/tree in `restore_policy.rs` and records additional effective inputs
and cross-cutting producers. It is source evidence, not a live process inventory,
quiescence receipt or permission to write partitions. All source groups inherit
the cross-cutting producers, even when their own API domain is enrolled.

| Producer boundary | Implemented state | Still required before capture |
| --- | --- | --- |
| Account and Config APIs | Typed owned permits and common activity drain | Integrate capture; retain native/web/config crash-recovery work separately |
| Firewall set/confirm/TLS downgrade and rollback timer | Typed follow-up permit, retained task stop/join, composed admission-first drain | Durable crash recovery and target firewall/service acceptance; integrate capture |
| Time set/sync and syslog set APIs | Whole-operation Config admission, owned file/service chains | Multi-file recovery, native init/daemon closure and canonical legacy-state capture |
| Other persisted settings APIs | Source paths assigned to groups | Enroll full operations and owned callbacks/commands, not just writes |
| Other backend timers/installers/restart tasks | Named in inventory | Close admission; finish or phase-aware cancel and join every owner |
| S95 watchdogs and service supervisors | Start/stop source inspected | Stop and join respawners before producers; no restart race |
| DHCP/Wi-Fi, SSH, optional gateways/daemons | Conditional service owners identified | Verify exact deployed ownership and completion; kill/pidfile deletion is not join |
| Local NanoKVM privileged sessions/scripts | Can affect all sources | Supported maintenance boundary or abort; never assume they only write listed paths |

The selected active config, cwd, configured identity/TLS paths and optional-app
home can differ from canonical restore destinations. Pending firewall/Wi-Fi/raw/
app transitions need an explicit completion/abort decision. Preserve authoritative
settings and regenerate derived runtime files from signed code; do not copy
arbitrary symlinks, shell defaults, executables or caches as trusted state.

Native `kvm_system` is a writer too: its AP state machine writes AP credentials
and invokes Wi-Fi init independently of HTTP. Rust hwmon, in contrast, writes
temporary telemetry rather than the preserved schema. Optional S96/S98 scripts
are not default-installed Buildroot init entries; source presence does not prove
an installed/running device service. Native library side effects need their own
evidence, not a conclusion from a path-name search.

Do not assume cgroup freezer or PID namespaces from a kernel version number.
Check the exact deployed capabilities before selecting a maintenance mechanism;
this inventory neither changes the kernel nor authorizes a new privilege model.
Unknown/unjoined producers must abort before the first partition write. Stopping
the backend alone does not establish this condition for daemonized descendants.
Limits on local NanoKVM administration do not gate autonomous HID/BIOS/terminal
work on the target computer during ordinary operation.

Run `make test-state-writer-inventory`. The source security-policy check also
runs the coverage validator. Missing/new/wrong-kind/duplicate members, unknown
schema syntax, empty tables, missing evidence and false runtime-authority claims
are rejected. This deliberately restricted Rust-constant parser is a source
coverage lint, not semantic call-graph analysis. A PASS explicitly reports that
runtime quiescence is **not established**. Runtime stop/join, production capture,
retained raw writer/ticket/early boot restore and target/release gates remain open.

The implemented firewall boundary is detailed in
[security-update-ownership.md](security-update-ownership.md#owned-firewall-transition).
Its stop means roll back and join, never implicitly confirm. Orphan pending state
or an observed failure aborts capture; explicit operator recovery is separate.
`AppState::drain_writers` composes this with admission and activity drain, not
external service closure. No production capture calls it yet.

`source_basis` records the reviewed source revision; the checker does not bind it
to the current Git revision or source contents. Evidence references are checked
for file existence only. Writer names, enrollment statuses and dynamic readsets
are manual review statements, not mechanically verified relationships. Tree
entries classify roots, not every possible descendant. A new producer can leave
the restore path set unchanged, so producer changes still require source review
even when this coverage check passes.
