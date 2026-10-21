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
| DNS/IPv6/Wi-Fi APIs and WOL cache | Whole-operation Config ownership, post-service publication and serialized cache RMW | Independent native clients/hooks/AP consumer, pending Wi-Fi resolution and multi-file recovery |
| PicoClaw model/default/token and Rust-initiated onboard | Config-owned Rust pair/onboard; startup/default no-op preserves the installed pair and refuses pending recovery; fixed broker operations bind retained home and installed pair generation, recover only before stopped launch, retain Update-only Stop through join | Ordinary API/S96 still legacy; profile/workspace/session/installer and independent native/onboard writers, full routing and pending-capture settlement remain open |
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

WOL target dispatch remains independent of local cache admission. If that
optional history is busy/paused or cannot be read, dispatch can succeed without
changing it. Rename/delete are normal Config mutations and fail on busy/error.
Wi-Fi SSID and password publication now both use mode 0600.

Native `kvm_system` is a writer too: its AP state machine writes AP credentials
and invokes Wi-Fi init independently of HTTP. Rust hwmon, in contrast, writes
temporary telemetry rather than the preserved schema. Optional S96/S98 scripts
are not default-installed Buildroot init entries; source presence does not prove
an installed/running device service. Native library side effects need their own
evidence, not a conclusion from a path-name search.

An AP API success publishes credentials and a request marker; it is not a
connection receipt. Draining API activity does not settle that native request.
The marker consumer and any in-flight init work must be stopped/joined and the
pending attempt explicitly completed or aborted before capture. Ordinary Wi-Fi
disconnect retains the legacy service/file behavior; it is not that maintenance
settlement protocol.

Do not assume cgroup freezer or PID namespaces from a kernel version number.
Check the exact deployed capabilities before selecting a maintenance mechanism;
this inventory neither changes the kernel nor authorizes a new privilege model.
Unknown/unjoined producers must abort before the first partition write. Stopping
the backend alone does not establish this condition for daemonized descendants.
Limits on local NanoKVM administration do not gate autonomous HID/BIOS/terminal
work on the target computer during ordinary operation.

The internal PicoClaw token is a derived local capability, not an extra preserved
schema member or a raw restore receipt. Creation is limited to startup/default
configuration under the Config permit. Missing/invalid request credentials never
create or replace it. The fixed-root store rejects malformed files and unsafe
metadata rather than silently repairing a live authority. Coordinated runtime
configuration/regeneration across raw restore and optional-home migration still
needs end-to-end acceptance; this enrollment does not close C1 or H2.
Rust JSON/YAML credential copies use the
[checked pair protocol](security-picoclaw-config-io.md). A private pending journal
is not silently added to the raw-preserve schema: capture must settle or reject
it under the effective-home/native-service barrier before reading canonical
files. Native publication/start-after-recovery, stale-temporary GC and all
external producer/service closure remain prerequisites; no runtime drain is proven.

A [dedicated native process owner](security-native-owner.md) now provides a
host-tested subreaper/pidfd scope for fresh launches. Static helpers are packaged
and current S95 routes KVM/hwmon/backend through the broker after fresh-boot
enrollment; this is not deployed device acceptance or capture integration. An
optional Pico slot now participates in native/all-role drains when enrolled,
but ordinary API/S96 does not route its lifecycle through that slot yet. It does
not adopt existing services. The broker freezes one lexical absolute home before
opening the native journal and retains it across drain/trial/rollback; backend
and optional Pico commands inherit that selection. Malformed explicit selection
refuses broker startup without falling back to the default. A fixed read-only
IPC query compares a caller's full home fingerprint with the live broker; it
does not tick lifecycle work, select a home, validate filesystem trust or grant
future start/capture authority. Separate fixed ensure/stop service operations
bind that fingerprint in each actual request. Ensure retains Update/Config,
settles the pair only for a closed owned scope, and compares the installed
generation before a fixed launch. Live generation checks refuse pending intent
instead of reading Rust's virtual committed view. Stop retains only Update until
receipt/reap/EOF and does not reacquire a caller's Config. These operations do
not stop or adopt an independent legacy process; API/S96/all-writer migration,
complete helper/script transition and raw capture acceptance remain open.
It therefore does not
upgrade any source group to runtime-quiescent. The broker's fixed local IPC and
explicit new-boot native journal recovery are host-tested components, not raw
restore authority. Watchdog/init/recovery integration and actual target support
remain required.

The boot receipt now binds the compiled five-script generation and exact
optional S96 presence/content. Same-boot add/remove cannot reuse Ready; malformed
or foreign script state is refused without repair. This is provenance checking,
not process ownership or a cooperative writer lease: the current S96 path is
still legacy and optional installer/native-service migration remains open.

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
