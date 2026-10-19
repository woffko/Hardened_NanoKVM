# Independent app-slot recovery component

This describes a source/host-tested rollback engine and early consumer gates,
not an activated journaled installer or a completed WP-04/C1 fix. The actual app
API still uses its legacy slot swap. The new helper is compile-bound into the linked RV64 backend and
packaged under `/kvmapp/system/bin`. Build recipes now install an independent
`/usr/libexec/nanokvm-app-recovery` copy, and the target backend attempts atomic
installation for an app-only bridge. S02 and individual consumer gates now invoke
it, but the trusted producer, legacy first-bridge target acceptance, helper migration and
device acceptance remain open. The full remediation scope is unchanged.

## Authority and fixed storage

The standalone `nanokvm-app-recovery` accepts only `status`, `recover` and `gate`.
There are no root, journal, stage, phase, force, prepare or commit arguments.
Recovery cannot publish a new app or issue a trusted installation receipt.

Production storage is fixed at `/etc/kvm/application-slot/current`. Root, `/etc`
and `/etc/kvm` must be protected root-owned directories on the same rootfs.
The slot store/current directories require root ownership and mode 0700. Opens
reject symlinks, magic links and mount crossings, including same-device binds.
Recorded slots must be root-owned, non-group/other-writable directories on the
same device. Legacy ownership requires an explicit installer migration before
this protocol is activated; the recovery helper does not silently chown paths.

The fixed store directory retains a nonblocking `flock`. Its inode is never
unlinked or replaced to release admission. Status takes a shared store lease;
recovery takes an exclusive lease and the existing shared app/system update
admission. The store owner explicitly unlocks at teardown so a concurrent fork's
pre-exec alias cannot prolong completed work. This is not descendant quiescence.

The canonical mode-0600 single-link regular `state` is exactly 512 bytes. It
contains a versioned magic, phase, explicit signed/manual/unsigned-lab import
kind, nonzero transaction ID, distinct old/new device+inode identities, archive
SHA-512, exact metadata/signature SHA-256 context, and bounded numeric x.y.z
version. Reserved bytes and the whole domain-separated SHA-256 checksum are
validated. These hashes detect corruption and retain context: they do not
perform RSA verification or authenticate an attacker-supplied manifest.

Only a future trusted producer may issue a record after authorizing the exact
archive. That producer must retain exact metadata/signature and protected key/
policy context where required; it does not exist in this component. Rootfs
protection, issuer provenance and the closed restore policy are mandatory.
Neither a copied p3 record nor a valid checksum creates installation authority.
Host tests require the new journal, temporary records and old/new code slots to
be absent from restore capture, rejected on restore import, and undeletable by
restore absence records. Legacy S01 p3 import and API p3 pending authority are
now retired; raw installation is temporarily refused in the development branch.
The authenticated raw/early-restore replacement is still an open C1 blocker and
must preserve these exclusions. Removal of the old path does not itself activate
early app recovery or authenticate old rootfs state from a compromised boot.

## Supported rollback layouts

`old` and `new` below mean the exact recorded directory identities, not names
chosen by a manifest. Only these layouts are admitted before recovery:

| Active `/kvmapp` | `current/new` | `current/old` | Recovery before commit |
| --- | --- | --- | --- |
| old | new | absent | Keep old; record rolled-back |
| absent | new | old | Restore old; record rolled-back |
| new | absent | old | Park new, restore old; record rolled-back |

All other layouts, missing/foreign identities, aliases or unsafe objects refuse
mutation and retain evidence. A terminal committed record additionally requires
new to be active; rolled-back requires old to be active. The candidate is always
retained at `current/new` after rollback, not deleted. Recovery never scans
orphan preparation directories, selects a temporary record, reads legacy p3
markers, or repairs an unknown layout by guessing.

For an uncommitted transaction, recovery first publishes `rolling-back` using a
fresh exclusive mode-0600 temporary, file sync, canonical rename and directory
sync. Mode 0600 is set on that newly created FD independently of inherited
umask; unsafe existing records are still refused rather than chmod-repaired.
If new is active, it is parked at `current/new` using NOREPLACE. The recorded
old is restored to `/kvmapp`, also NOREPLACE. Root/current/store directories are
synced, the resulting layout is checked, and `rolled-back` is published. Errors
leave the last durable state and evidence for a fresh inspection. Torn temporary
records are retained but never selected as authority or reused for publication.

Repeated recovery of a terminal record validates the layout and completes the
directory durability barrier without replaying renames. `committed` denotes
publication state only, not accepted runtime health. The first-restart/boot
handshake, rollback policy after a new runtime failure, and actual first-start
acceptance are still to be designed/wired and tested before the new installer
can be considered complete. `no-transaction` is diagnostics, not boot-good or
permission to execute an arbitrary app directory.

Absence means no canonical `current` transaction, even when protected unpublished
preparation siblings remain. Such siblings are retained but never scanned,
decoded, selected or promoted by recovery/bootstrap. Installing the trusted
backend's compile-bound independent helper in that state is the same operation
as the ordinary historical-absence case; it does not use orphan bytes as authority
and does not publish/execute an app. Unknown installed helpers still refuse.
The future trusted producer must explicitly handle its retained preparation
material; no deletion or automatic orphan activation is implied here.

## Early consumer integration (development branch)

`/etc/init.d/S02apprecover` invokes the independent helper after S01 mounts and
before app consumers. A failed init script does not necessarily stop rcS, so
the DHCPv6 client/hook path in S30eth, Wi-Fi AP credentials in S30wifi, S95 start/
restart and native/backend/watchdog/delayed-hwmon launch paths also call the fixed
helper. Ordinary Ethernet IPv4/SLAAC and STA startup do not read `/kvmapp` and
are not gated by this app-slot protocol. This is NOT the future global raw
identity/restore boot gate; raw installation remains temporarily refused.

`gate` first reads/validates the protected journal and exact slot layout. A
terminal committed/rolled-back state or absence returns without acquiring common
update admission: the restart requester may still hold that admission. An
uncommitted state enters the existing recovery path, which must acquire it.
A concurrent consumer therefore receives Busy while an installer owns admission,
rather than rolling that installer back. Corrupt/foreign layouts fail closed. NoTransaction preserves
the pre-existing trusted legacy/factory path; it is not a new authorization,
candidate signature, bootstrap ticket or runtime-health receipt.

The backend embeds exact S02/S30eth/S30wifi/S95 source bytes. Its startup first
establishes/verifies the static helper and protected init directory, then
atomically publishes these compile-bound scripts. If support establishment fails,
it skips new critical gate publication and keeps management for diagnosis.
Ordinary script-copy failures still fail startup. The publisher establishes mode
0755 on its fresh FD independently of umask. S95 no longer recopies these four
scripts (including itself) from a possibly rolled-back bundle. The app install
prerequisite verifies their exact bytes, owner/mode/link count and protected
parents, not just presence of a helper. An absent optional hwmon remains a normal
startup condition; a denied recovery gate does not.

Optional S96 onboarding/skill/profile consumers are gated. The picoclaw API also
runs the fixed helper before selecting either an already installed S96 or the
bundled fallback for start/onboard, so an older installed script cannot bypass
that API gate. Stop does not depend on recovery or execute either script: it
uses fixed `/bin/busybox killall picoclaw`, preserving S96's existing best-effort
stop semantics even when the app slot is unresolved. This is not process-tree
quiescence or the remaining MCP worker cancellation/revocation acceptance.
No optional service is installed/enabled merely to update its guards. The API
command has a 20-second deadline and owned direct-child cleanup; a killed recovery
must be resumed from durable journal state, not assumed complete. This does not
implement the separate unprivileged picoclaw/capability work or alter autonomous
target-computer HID operations. Manual root execution is not sandboxed.

These are startup snapshot checks, NOT a retained native launch capability or
process-tree quiescence proof. State can change after a gate returns. Existing
system boot-health monitoring and other native/configuration producers still
need the composed native-owner lifecycle; passive app-file health probes are
not individually fenced by this protocol. Do not claim that all concurrent
runtime reads/writes are excluded or that an app install is now crash-safe.

**Legacy first-bridge target acceptance is still a release blocker.** An old S95
can copy new bundled gated scripts before the backend has established the helper.
In RC12 source `387793ab944437bbedc534d2ba231dd88d1fd2ca`, the old app API first
swaps `/kvmapp`, then invokes S95 `restart`. S95's `start_runtime` calls
`install_boot_scripts` before starting either native runtime or backend; its
copier also overwrites S95 itself in place. Safe continuation of that already
running shell must not be assumed. The old backend's own script synchronization
occurs only after it has been launched and cannot close this earlier window.
Power loss in that window is not covered by the backend's safer publication
order alone. The archive-delivery profile below addresses premature gate/self-copy
publication for exact RC12/app42 inputs at source/host scope. It is not the full
legacy migration, old-installer crash-safety or helper-version lifecycle. Old
backends may also overwrite rootfs gates after rollback; this still needs acceptance.

Host user-namespace/chroot fixtures exercise the actual fixed-root gate with
held admission in no-transaction/terminal states, Busy for active nonterminal
states, and recovery of all three supported interrupted layouts. Shell fixtures
check refusal before side effects, repeated launch guards, S02 exit propagation,
protected-script non-copying and rootfs validator errors. Historical ungated
bodies are rejected structurally, never executed on the host. Source guards for
the picoclaw API (including independent Stop selection) are not HTTP/device
acceptance; no live processes are signalled by those tests.

### App archive delivery versus full-image staging

`package-rust-kvmapp.sh` now keeps its ordinary full-image staging tree canonical,
with all four current compile-bound scripts. The app archive is produced from a
separate private copy. That copy omits S02apprecover/S30eth/S30wifi and carries an
exact historical S95 from app 2.0.42, SHA-256
`8030d0f81581a417eca91e3db7e0c3d96cba197b519022d7c73c3c5caca05365`.
The historical source and provenance are retained as a non-executable data asset
under `support/update-compat/rc12`, not as the current rootfs init script.

S95 cannot simply be omitted: the old app archive validator requires it. For the
exact supported installed RC12/app42 S95 bytes, the old copier's equality check
leaves the executing shell untouched. Absent ancillary sources leave the old
rootfs files untouched too. The new backend then verifies/installs the independent
helper and publishes its compile-bound canonical scripts. Once current rootfs S95
is installed, its protected-script skip never recopies the archive's legacy S95.
Full SD/raw rootfs construction uses the unchanged canonical stage, not the
app-archive view. Do not substitute an unpacked app archive for that image stage.

`app-boot-delivery.py` refuses a backend lacking any exact canonical embedded
script, a changed historical asset, or a final archive with premature gate paths,
aliases, links, special objects, duplicate/foreign/missing S95 or exceeded bounds.
The manifest labels `app_archive_boot_profile: rc12-compat-bootstrap-v1`; this is
build consistency metadata, not a signature, runtime receipt or recovery authority.
The normal app metadata/checksum/signature rules are unchanged.

This profile does not add another user bridge step: app 2.0.40/41 still need the
existing published 2.0.42 key bridge; exact app42 proceeds to one fixing app.
It does not authorize arbitrary customized/unknown old S95 bytes, for which the
old copier could still overwrite its executing script. Exact legacy init identity
and first-restart/power-loss behavior must be verified before any device acceptance.
The already-vulnerable portion of an old install cannot be made retrospectively
atomic or safe against prior root compromise. Keep USB-data isolated and use
trusted reflash/recovery for unsupported or compromised states.

Host tests cover the exact old copier's equal/missing-source behavior and detect
the pre-fix copy attempt, plus package fault rejection and unchanged full-image
staging. Repeated packaging of the same actual RV64 inputs gives equal archives;
this is NOT independent backend/full-pipeline reproducibility. A retained-input
Rust test feeds those exact archive bytes through private production extraction
and candidate preflight without invoking installation, helper migration or restart.
No `/kvmapp` recovery-helper execution fallback, forced helper replacement,
journal deletion or trust relaxation is introduced.

## Build and verification boundaries

`server-rust/scripts/build-app-recovery.sh --locked --offline` builds this helper
statically as an ELF64 RV64 executable in the separate restore-runtime target
directory. It refuses an ELF interpreter or shared-library dependencies/RPATH/
RUNPATH. The recovery
component must not load `/kvmapp` libraries before establishing its boundary.
This command builds/checks only; no installation, boot-hook activation, signing
provenance or independent A/B reproducibility is implied.

The linked backend build first builds both static helpers in the separate
restore-runtime target directory. It requires a distinct `NKAPPBT1` app-recovery
envelope as well as the existing `NKSSHRT1` SSH envelope. Both inputs are
validated before either Cargo output is written. Host/unbound helper builds
contain no usable binding; neither envelope domain can substitute for the other.
The backend validates and retains the embedded app-recovery image. There is no
runtime path, environment, bundled-file or manifest fallback.

The app packager extracts the exact embedded image exclusively into
`kvmapp/system/bin/nanokvm-app-recovery` and records its SHA-256 and size in the
package inventory. An unrelated bundled helper cannot replace a missing or bad
binding. Buildroot checks source helper/backend equality, restores the bundled
helper after generic ELF fixups and checks the final pair again. These are
build/package consistency checks, not RSA release authentication or permission
to execute code supplied by an attacker. A helper living only inside `/kvmapp`
still cannot recover a missing app slot.

### Independent publication and app-only bridge

On linked RV64 startup, after closing legacy USB storage and loading config,
the backend prepares app recovery and all four native executables under one
shared app/system admission lock. A retained `BootSupport` guard holds admission
through the subsequent compile-bound consumer-script publication, not merely
through the helper rename. Missing/invalid native support withholds publication;
it is not an app-slot success or a native-process ownership receipt.
All of `/`, `/usr` and `/usr/libexec` must be root-owned,
non-group/other-writable and on the same rootfs, with symlink/mount crossings
rejected. A missing `libexec` directory may be created under the protected `/usr`;
no existing directory or helper is chmod-repaired. Publication uses only the
compile-bound bytes, not the bundled helper as a runtime fallback.

An existing helper must be a single-link regular root-owned file of mode 0755.
Current-helper verification requires exact size and exact bytes. It is opened
for inspection without data access, then reopened read-only/nonblocking, with
inode/layout checks before/after the read. An unknown or unsafe helper is
retained and refused, not overwritten. No installed helper is executed to
identify or authorize itself.
First helper publication supports the historical absence case; this does not
prove the complete old-installer/first-restart bridge described above.
The directed v1 predecessor migration below covers only explicitly pinned
previous bytes. Old-backend rollback and transitions to a different journal
protocol still need separate lifecycle acceptance. Do not delete journals or
replace files manually to turn a mismatch into a successful check.

A missing helper is written to a fresh exclusive random sibling, chmodded only
through that new FD, file-synced, renamed with NOREPLACE and directory-synced.
The result is rechecked. A competing canonical winner must be exact; an unknown
winner and all torn temporaries are preserved. Temporary names are never read
as fallback or selected as authority. A pending, terminal or corrupt canonical app-slot
journal never permits a new helper to be installed over missing support.

### Directed v1 helper migration

Startup holds the same update admission from fixed-root journal inspection
through helper publication. The internal publication primitive requires a
borrow of that live admission owner. It does not call recovery while holding
the lock, avoiding nested admission. Corrupt/foreign journal or layout fails
before publication; no journal is retired or rewritten by bootstrap.

| Validated app-slot state | Exact current helper | Missing helper | Pinned v1 predecessor |
| --- | --- | --- | --- |
| No transaction | Verify only | Install exact embedded helper | Forward migration |
| Committed / rolled-back v1 | Verify only | Refuse | Forward migration |
| Nonterminal v1 | Verify only | Refuse | Refuse |

Unknown/unsafe helpers are refused in every state. The build-owned predecessor
registry binds both size and SHA-256, not an executable's version output or a
runtime manifest. The initial entry is the retained development helper from
`89aa736`, 373,048 bytes, SHA-256
`9095522caf08d9f0a0bf2f70917b9ce733930d9cedb85f50249b745cc2b535e8`.
Historical RC12 has no independent helper. Adding a predecessor requires exact
byte and journal compatibility review; a matching hash is not a new release
signature or authorization from an untrusted app directory.

Migration verifies the predecessor before staging, writes only the compile-bound
new image to a fresh exclusive sibling, establishes mode 0755 on that new FD and
syncs it. It rechecks the prior digest and canonical inode, then uses atomic
`RENAME_EXCHANGE`: the canonical name is never intentionally absent or updated
in place. After directory sync it verifies the exact new canonical image and
retained old inode. The old file stays under the random sibling name as evidence;
it is never selected as an executable fallback or transaction authority.

An error after exchange does not mean nothing changed and does not assert
rollback. Startup keeps authenticated management for diagnosis and skips new
critical-script publication on that failure. A fresh invocation must inspect
canonical state: if the new helper is already exact, it completes file/directory
durability without exchanging again. Torn/retained sibling files are not scanned
or selected. Cooperating privileged writers must honor update admission; this
does not sandbox hostile root or promise protection against an unrelated
privileged writer racing after the final check.

Host tests cover the state decision, pinned actual old RV64 bytes (never executed),
unknown/unsafe refusal, competing admission, SIGKILL at staging/exchange boundaries,
pre-exchange canonical replacement and a post-exchange sync-error path. Migration
unit tests supply status enums; the separate bound-root gate now calls the actual
fixed-root `ensure_installed()` in disposable user-namespace/chroot children.
It independently encodes v1 records using real directory device/inodes and checks
terminal/nonterminal/corrupt/foreign/orphan cases, exact-current verification,
both update-admission and store-lock contention, and SIGKILL before/after exchange
with repeated inspection. Actual old/new RV64 files are data, never executed.
This covers the bootstrap entry, not the full main/S95/native lifecycle, target
startup or physical power-cut acceptance. The retained-input unit test is
explicitly ignored by default and was run in
the full `--include-ignored` gate; ordinary default tests do not cover that input.
The new test image is synthetic, not a deployable successor helper. This
is forward publication, not automatic executable rollback, the trusted app-slot
producer, retained native ownership or full C1 closure.

Run `server-rust/scripts/test-app-bootstrap-root.sh` for the bound-root gate. It
requires matching retained backend/helper build inputs and the exact predecessor
evidence; it verifies their binding before compiling the explicit
`app-bootstrap-bound-test-fixture` feature. Missing/unbound inputs fail, rather
than silently skipping composition checks. The feature only selects a `cfg(test)`
module and adds no shipped CLI, root override or runtime fallback. The harness
bounds child execution and captured output, drains pipes and kills/reaps its own
direct child on timeout or assertion unwind. This is not a generic process-tree
supervisor or a bounded-kernel-I/O guarantee. Ordinary default tests do not
select this retained-input gate.

If the backend has already launched, a helper-bootstrap failure alone is logged
without terminating it, preserving authenticated management for diagnosis.
The target app install API independently rechecks the exact app helper, complete
native family and critical consumer scripts, and requires no app-slot transaction before its first legacy
slot/backup mutation, while
already owning shared update admission. This is an installation prerequisite,
not a durable receipt or a claim that the remaining legacy swap is crash-safe.

Buildroot installs both copies up front and restores/verifies both after ELF
fixups. The legacy SD assembler also writes a mode-0755 root-owned independent
copy. `scripts/verify-app-recovery-rootfs.py` reads an ext image without mounting,
checks protected independent parents/owner/mode/link count and verifies both
helper copies against the final backend's exact embedded image. Its real ext4
fixtures include missing/mismatched payloads, missing binding, symlink/hardlink,
permissions, ownership and oversized data. These are not full pipeline/boot gates.

Current generic/Buildroot rootfs validators require this new protocol by default;
they must reject historical images missing independent recovery, not silently
skip it based on a version label. Historical RC12 validation remains separate:
`scripts/verify-rc12-raw-bundle.sh` pins the accepted rootfs/boot hashes and does
not call the new rootfs gate. Use its signed mode and the matching retained
metadata/signature/public key for signed RC12 evidence. This is not a way to
authorize a new candidate without independent support.

`server-rust/scripts/test-embedded-app-recovery.sh` checks host capture of the
actual static RV64 input, without executing that foreign-architecture image.
The binding CLI tests cover distinct domains, corruption, ambiguity, ELF
constraints, exact extraction/verification, cache conflicts and unsafe input
types. Package and post-build fixtures additionally reject missing, corrupt,
duplicate or wrong-domain bindings and helper mismatch. These synthetic fixtures
do not replace a real target package, full rootfs build or device gate.

Host tests cover strict framing/context, each supported uncommitted phase/layout,
idempotence, terminal layout mismatches, foreign/missing/symlink objects, FIFO/
hard-link/permissions/device checks, a subprocess with restrictive umask,
corrupt canonical records, ignored/preserved
torn temporaries, same-inode lock admission and inherited-description teardown.
Real subprocess SIGKILL tests interrupt all 12 recovery record-publication and
slot-rename boundaries and then recover twice. These are process-crash tests,
not physical power-loss, ext4 write-cache or target acceptance.

## Remaining activation prerequisites

- Trusted journal producer with same-filesystem durable preparation/publication,
  exact signed/manual authority and retained metadata/key/policy context.
- Full pipeline/target acceptance of independent rootfs installation and the
  atomic app-only bootstrap, including actual I/O failure and mount negatives.
- Complete helper-version lifecycle across subsequent app updates. The pinned
  v1 forward-publication path and fixed-root decoded-journal bootstrap are
  host-tested, but target startup, released successor/predecessor pairs and
  old-backend rollback still
  need acceptance. This remains required for WP-04, not an implicit waiver of
  app-only updates or permission to replace unknown support.
- Full target/first-bridge acceptance of the archive-delivery profile and the
  early/individual consumer gates; verify exact old S95 identity, establish
  independent support before publishing gates, and preserve legacy rollback.
  Nonzero rcS exits alone are not gates.
- Native/S95/watchdog/raw lifecycle coordination, first restart and runtime
  acceptance; do not replace code used by a running shell/executable in place.
- Actual installation crash tests, ENOSPC/I/O failure, target mount negatives,
  legacy migration and complete device/release acceptance.

The app API now refuses missing/mismatched independent support/scripts or any
app-slot journal before legacy slot mutation. Early gates invoke recovery, but
the app API still does not publish a journal. No account, SSH setting, signature
algorithm/key ID,
version, release channel or accepted image is changed by this component.
