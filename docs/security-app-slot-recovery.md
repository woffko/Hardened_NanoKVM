# Independent app-slot recovery component

This describes a source/host-tested rollback component, not an activated
installer or a completed WP-04/C1 fix. The actual app API still uses its legacy
slot swap. The new helper is compile-bound into the linked RV64 backend and
packaged under `/kvmapp/system/bin`. Build recipes now install an independent
`/usr/libexec/nanokvm-app-recovery` copy, and the target backend attempts atomic
installation for an app-only bridge. Early boot invocation and device acceptance
are still absent. The full remediation scope is unchanged.

## Authority and fixed storage

The standalone `nanokvm-app-recovery` accepts only `status` and `recover`.
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
restore absence records. The currently unintegrated legacy raw path is still
an open C1 blocker; it must not be allowed to overwrite this future authority.

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
the backend attempts fixed-rootfs bootstrap under the shared app/system
admission lock. All of `/`, `/usr` and `/usr/libexec` must be root-owned,
non-group/other-writable and on the same rootfs, with symlink/mount crossings
rejected. A missing `libexec` directory may be created under the protected `/usr`;
no existing directory or helper is chmod-repaired. Publication uses only the
compile-bound bytes, not the bundled helper as a runtime fallback.

An existing helper must be a single-link regular root-owned file of mode 0755,
exact size and exact bytes. It is opened for inspection without data access,
then reopened read-only/nonblocking, with inode/layout checks before/after the
read. A different or unsafe helper is retained and refused, not overwritten.
The first fixing app supports the historical states where this path is absent;
replacement of a different independently installed helper needs a separately
reviewed protocol migration. Do not delete journals or replace files manually
to turn a mismatch into a successful check.

A missing helper is written to a fresh exclusive random sibling, chmodded only
through that new FD, file-synced, renamed with NOREPLACE and directory-synced.
The result is rechecked. A competing canonical winner must be exact; an unknown
winner and all torn temporaries are preserved. Temporary names are never read
as fallback or selected as authority. A pending, terminal or corrupt app-slot
journal never permits a new helper to be installed over missing support.

Bootstrap failure leaves authenticated management available for diagnosis.
The target app install API independently rechecks the exact helper and requires
no app-slot transaction before its first legacy slot/backup mutation, while
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
- Reviewed helper-version migration across subsequent app updates; the current
  exact-existing/no-replacement rule is a fail-closed prerequisite, not a final
  upgrade lifecycle. This remains required for WP-04 acceptance, not an implicit
  waiver of app-only updates.
- Recovery before the first boot app consumer, with fail-closed consumer gates;
  a failed init-script exit alone must not be assumed to stop rcS.
- Native/S95/watchdog/raw lifecycle coordination, first restart and runtime
  acceptance; do not replace code used by a running shell/executable in place.
- Actual installation crash tests, ENOSPC/I/O failure, target mount negatives,
  legacy migration and complete device/release acceptance.

The app API now refuses a missing/mismatched independent helper or any app-slot
journal before legacy slot mutation. It still does not publish a journal or
invoke recovery at boot. No account, SSH setting, signature algorithm/key ID,
version, release channel or accepted image is changed by this component.
