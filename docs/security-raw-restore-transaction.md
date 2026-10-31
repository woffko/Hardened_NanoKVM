# Authenticated raw restore transaction

Status: implementation in progress on the security remediation branch. Capsule
crypto, closed-schema archive capture/validation, canonical app/native-identity
checks, SSH configuration-path guards/snapshots, protected ticket persistence and
descriptor-relative source I/O are implemented and host-tested. The development
branch has retired the legacy raw launcher and plaintext p3 boot restore. Raw
installation now fails explicitly before the old launcher/marker/partition-write
steps until the authenticated replacement is integrated. This temporary barrier
is not a releasable replacement or fixed C1; raw functionality must return before
candidate acceptance. Previously released RC12 artifacts are unchanged.

## Trust boundaries

- Rootfs holds account/trust/update authorization, app archives/slots and exact
  verified signed metadata. `/data/media` is the only USB image namespace.
- A separate private p3 directory may hold large raw payloads and the encrypted
  restore capsule. A file, hash, marker or stage record on p3 grants no authority.
- A one-time restore ticket and key live on protected p1, never alongside the
  capsule, in an exported image, release assets, logs or diagnostic JSON. The
  public production RSA key/trust policy stays unchanged.
- Raw writing destroys p1 and rootfs. The isolated runtime writer must retain
  the authorized ticket/key and required helpers/libraries in private tmpfs,
  then durably put the ticket onto the newly written bootfs before reboot.
- Interrupted raw partition writing is manual recovery, not atomic A/B rollback.
  Losing p1's ticket must never cause an untrusted p3 preserve tree to restore
  privileged files or the system to fall back silently to a default identity.

## Exact system metadata at install (connected to the system API)

The online system downloader retains the selected channel's exact JSON bytes
and detached signature, rather than re-serializing `SystemLatest`. After archive
and manifest validation it publishes one rootfs receipt:
`/etc/kvm/update-trust/system-metadata.v1`. The directory is owner-0 `0700`, the
regular single-link record is `0600`, and neither may be reached through a
symlink or nested mount. The bounded binary framing carries at most 64 KiB JSON
and 16 KiB signature; it is not a new signing format or a trust-policy change.

Publication uses a private random exclusive temporary file, file fsync,
descriptor-relative rename, then directory fsync under an exclusive store lock.
Malformed existing canonical receipts are preserved and require operator
recovery, never silently overwritten. Deterministic I/O fault tests establish
complete old/new records at these boundaries, not physical power-loss proof.
Process termination may leave an untrusted random temporary record, which is
never imported as authority.

Every system install rereads persisted Config without falling back to stale
startup policy, reparses the exact receipt, resolves the current allowed key and
verifies the detached signature again. Explicit laboratory unsigned permission
is also rechecked; a cached success cannot grant it. The mutable p3 stage record
must match the authenticated metadata but is not itself authentication. Legacy
staging without a protected receipt requires **Download and Verify again**;
there is no automatic trust import of an old JSON/hash/marker.

New downloads no longer recursively delete the system stage root. Backups,
preserve state, old archives and unknown recovery files remain. Any existing
root pending record or legacy raw marker, including malformed data or dangling
links, conservatively blocks a new download/install until recovery is inspected.
This is denial/retry protection, not authorization from a legacy marker.

### Retired legacy authority (development-only transition)

`S01fs` no longer imports the p3 plaintext preserve tree, privileged configuration,
accounts, optional executables/init scripts or update trust. Its old permission
fixups, including weakening `server.yaml` to mode `0644`, are removed.

Its partition steps are re-runnable (L-B10). p2 is grown to its fixed end only
when `/sys/class/block/mmcblk0p2` says it ends before 8192MB, so the partition
table is rewritten on a freshly written card and never again; `resize2fs` still
runs every boot, because a raw update writes a smaller filesystem into the same
partition. The data partition is created only when p3 is absent, and formatted
only when this script created it: `/etc/kvm.disk0.creating` is written before
`mkpart` and removed after `mkfs.exfat`, so a boot interrupted between the two
formats the still-empty p3 on the next boot, and an existing p3 is never
formatted. `scripts/test-s01fs.sh` runs these functions under sh and BusyBox sh
with recording stand-ins for `parted` and `mkfs.exfat`. The script has not run
on a device since this change.
`S95nanokvm` selects only the rootfs file-update pending record, never the p3 raw
marker, and does not delete that marker during auto-confirm.

The Rust API likewise has no p3-to-pending fallback or marker-staleness heuristic.
Status reports legacy object presence/inspection errors without opening its
contents. Confirm reads only the fixed rootfs pending path; confirm and rollback
leave legacy p3 evidence untouched. Rootfs pending parse errors are reported,
not silently converted to absence. That legacy rootfs reader rejects final
symlinks/special files and reads at most 4097 bytes for a 4096-byte limit; it is
NOT the new authenticated ticket protocol, a pinned-ancestor implementation or
proof of provenance after an already compromised historical boot. No cleanup
or automatic trust import of such a boot is implied.

The detached shell launcher, its runtime copying and raw marker publisher are
removed from production. Its historical generator remains `cfg(test)` only, with
explicit historical-only test names; those tests do not prove preservation by
the current build. Old `/proc` writer detection remains diagnostic, not a launch
or completion receipt. The administrative runtime-repair script also no longer
copies TLS identity from the plaintext p3 preserve tree; separate reviewed TLS
recovery is required if identity is missing.

The current raw install API retains the existing configuration permission gate,
then returns a development Conflict explaining that authenticated writer/restore
integration is incomplete and no partition write started. Normal file-update
installation remains separate. Existing archive preflight/extraction still runs
before raw dispatch; the barrier is not a claim that the whole API performs no
staging I/O. The new raw writer, restore-required signed-image
discriminator, protected early applier and complete settings/identity preservation
are mandatory next integration, not deferred optional features. No candidate may
be accepted or deployed as the finished security migration with this barrier.

Disposable host fixtures execute S01 and the S95 selector with inert commands,
show forged p3 state cannot change fixture account/config/code bytes or modes,
and retain all legacy evidence. Rootfs gates compare installed and bundled init
scripts and reject the known legacy selectors/inspection failures. These are
source/fixture regressions, not a full Buildroot pipeline, physical boot, raw
preservation or protection against arbitrary equivalent malicious source code.

Archive downloads use a pinned stage directory and a random exclusive `0600`
file. Curl receives no output pathname, user curlrc or stdin; only HTTPS and
HTTPS redirects are allowed. Stdout streams through one 64-KiB buffer with an
exact signed-size limit (maximum 2 GiB), a wall deadline and direct-child
kill/reap handling. There is no stdout append/retry; a failed transfer is retried
as a fresh download by the caller/user. No whole-archive memory buffer is used.
Only the owned temporary member is removed on failure. The canonical archive,
progress and stage-record names are replaced by rename, never opened through
old symlinks/hardlinks for writing; outside target contents are left unchanged.

Before fresh extraction, cached-receipt commitment and install, the API copies
the entire public update archive into a separate anonymous disk snapshot while
checking exact size/EOF and both authenticated SHA-256/SHA-512 digests. After
fsync it independently reopens that inode as kernel `O_RDONLY`, checks inode/
device/length/link count/access mode, and closes its sole writable description.
Extraction reads only this snapshot. Replacing or overwriting the original
archive after this point cannot change the bytes being parsed. Cache reuse also
checks the canonical archive, not merely its size and extracted tree. Production
keys/algorithms are unchanged; the snapshot API is not itself a signature proof.

On filesystems supporting it, snapshots use `O_TMPFILE|O_EXCL`. The existing
exFAT p3 has no tmpfile operation: only on actual exFAT, an exclusive random
**empty** public temporary file is unlinked and the directory synced before the
first byte is copied. No data-bearing name remains. Other unsupported filesystems
fail closed. This explicit public-release path must never be reused for restore
plaintext, accounts, tickets or keys; secret spools remain strict rootfs
`O_TMPFILE|O_EXCL`, without a named fallback. The one deliberate parent-side
`/proc/self/fd` reopen checks actual procfs and the exact owned anonymous inode;
it does not mount host proc inside the native sandbox or accept arbitrary paths.

Snapshot construction uses one 64-KiB buffer, not archive-sized RAM. It needs
up to one additional compressed-archive size of free staging disk while active;
space/I/O failure returns no snapshot before any partition write. Vendor-kernel
exFAT/procfs execution and target storage/performance remain acceptance gates.

## Direct bundle manifest and raw-image preflight (connected, transitional)

`server-rust/src/api/system_update_bundle.rs` reads the first `manifest.json`
directly from the authenticated anonymous archive, with a 128-KiB bound before
allocation. The API uses that manifest after extraction; it no longer reparses
an extracted p3 manifest. Format v1/v2, release version, target and required app
version must match the authenticated metadata. Cached receipt commitment also
runs this preflight. The public RSA keys and signing format are unchanged.

For raw bundles, exactly one BOOT and one ROOTFS image are required, with no
file-install entries. Only `payload/`, `payload/images/` and the two exact image
paths are admitted after the first manifest. Image order is independent of JSON
order. Existing plain and gzip image forms are supported, including mixed
compression. Both total stored and expanded image sizes are checked against a
2-GiB budget; declarations cannot cause image-sized memory allocations.

The reader checks raw GNU/USTAR headers before consuming any extension body.
It rejects links, devices, FIFO, sparse/GNU/PAX extensions, other members,
duplicates, aliases, non-octal size/mode/checksum fields and unsafe mode bits.
Header ownership/timestamps are signed bytes but never applied as authority.
Member padding must be zero. Two zero tar blocks are required, followed by only
complete zero blocks up to 64 KiB total trailer padding, then actual gzip EOF.
Hidden concatenated tar archives, a second gzip member, arbitrary suffix bytes,
truncation and bad gzip CRC/ISIZE are rejected.

Each image is copied into its own anonymous, independently reopened kernel
`O_RDONLY` snapshot. Gzip images require the stored member's exact size/SHA-256
and the expanded image's exact size/SHA-256, plus footer/EOF validation. Plain
images require exact size/SHA-256. Expected hashes come from the direct manifest
inside the already authenticated archive, not from stage JSON. Only after the
whole bundle passes are both descriptors returned, in BOOT/ROOTFS order. Failed
validation drops every in-progress/completed image snapshot. The SHA-256-only
image capture uses static dispatch and does not calculate an unused SHA-512.

This currently costs up to two archive sizes (canonical/download plus frozen
archive) and the combined expanded image size, in addition to retained staging,
recovery and other data. All are disk spools, not whole-image RAM buffers. There
is no reservation/physical free-space guarantee; ENOSPC fails preflight before
partition writing. In the transitional production path the expanded snapshots
are discarded **before** legacy extraction, avoiding an additional simultaneous
extracted-payload copy. Target card latency, wear, free-space requirements,
exFAT/vendor-kernel behavior and power-loss cleanup still need acceptance.
For retained raw.12 the expanded pair is 1,627,389,952 bytes; with two
57,144,130-byte archive copies, preflight alone can occupy about 1.62 GiB.
The historical manifest's 640-MiB `required_free_bytes` is not an adequate budget
for this new path. Compute/check the transaction's actual peak requirements
before release; do not silently treat that old hint as a storage reservation.

**No production raw writer consumes these descriptors yet.** The old mutable-path
launcher is removed and raw installation is explicitly blocked. An isolated
descriptor-bound writer and signed runtime binding remain required before C1
closure. File-update bundles use the direct
bounded manifest but retain their legacy remaining payload/framing validator;
the closed raw framing claims above do not apply to the non-raw early return.

**C1 remains open.** The snapshot closes later source-inode mutation but is not
protection from malicious local root or raw writes to its backing filesystem.
Extraction destinations, some legacy record reads and the remaining future
raw/early integration are not yet an immutable descriptor-owned transaction.
USB p3 exclusion, isolated writer,
signed-target runtime/rootfs binding, protected tickets, early fail-closed apply,
private app staging and device/crash/release gates remain mandatory. Do not ship
this partial system-API improvement as the completed security migration.

## Public raw-image descriptor channel (component, not production writer)

`update/raw_transport.rs` supplies a one-shot `AF_UNIX/SOCK_SEQPACKET` pair,
with no socket pathname, listener or network port. It uses the already pinned
`rustix 1.1.4` safe `SCM_RIGHTS` APIs (`net` feature, no lockfile/version change
or new unsafe code). This does not authorize an update: the caller must supply
already authenticated immutable BOOT/ROOTFS snapshots, with all writable owners
closed and p3 excluded from raw export. Readonly/nlink checks alone cannot prove
those prerequisites or protect against malicious local root/backing-store writes.

The fixed 137-byte public record is independent of machine endianness:

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 8 | `NKRAW001` transport format |
| 8 | 16 | Expected public transaction ID |
| 24 | 1 | Expected version length, 1–64 |
| 25 | 64 | ASCII version, zero-padded |
| 89 | 16 | BOOT/ROOTFS sizes, big-endian u64 |
| 105 | 32 | BOOT/ROOTFS device/inode pairs, big-endian u64 |

Context comes from the trusted transaction, not deserialized p3 state. Total
image size is bounded to 2 GiB. Sender and receiver are consumed by their one
operation. Source/received FDs must be distinct anonymous regular files, same
effective UID, exact sizes, safe mode, actual `O_RDONLY` and `FD_CLOEXEC`.
The receiver checks the record against its expected context, exact FD count,
inode identities and kernel `MSG_TRUNC/MSG_CTRUNC`; received FDs are atomically
`CMSG_CLOEXEC`. Failed validation closes completed/unconsumed ancillary FDs.
Endpoints have two-second socket send/receive timeouts and expected creator
PID/UID checks. `SO_PEERCRED` identifies the socket-pair creator, not the child
PID after fork/exec. These checks are not signature/ticket authentication.

The returned bounded image cursors use `pread`, not the shared open-description
offset inherited through `SCM_RIGHTS`. They expose no File/FD/write/Clone API.
Only one packet is processed, then the receiver closes; queued extra packets
cannot become further commands/inputs and their queued FD references are freed.
This is not a claim that all possible packet suffixes were read/rejected as EOF.

The child endpoint moves into `Command` stdin without `pre_exec` or raw-fd
ownership conversion. A fresh helper must duplicate stdin with
`F_DUPFD_CLOEXEC`, redirect/close the original fd0 alias, then adopt its owned
endpoint. The parent must drop the configured `Command` after spawn, not retain
another endpoint alias. No process-global stdio/fd closing is performed by the
library. Sending successfully means **queued only**; job ownership/child terminal
state and durable transaction acceptance must be checked separately.

Current evidence includes host unit tests, actual PublicSnapshot transfer and a
real exec-boundary fixture. The fixture is **not** an isolated production writer
and is compiled only with `sandbox-test-fixture`. There is no production raw
caller, native runtime provenance, partition write, secret capsule/ticket handoff
or early restore connected to this transport yet. C1 and all device/release gates
remain open. The future writer must also close unrelated inherited vendor FDs
and run from a protected retained runtime before the running rootfs is destroyed.

## Capsule v1 (implemented core)

`server-rust/src/update/restore_capsule.rs` uses ChaCha20-Poly1305 with RustCrypto
STREAM BE32. It uses the library's counter/final-block construction, not a custom
chunk nonce/tag scheme. Dependencies are exact-pinned existing lockfile versions:
`chacha20poly1305 0.10.1` and `zeroize 1.9.0`; no package version was upgraded.

The 104-byte public header is also the exact associated data for every frame:

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 8 | Magic/format `NKCAP001` |
| 8 | 16 | Fresh random transaction ID |
| 24 | 8 | Plaintext length, big endian |
| 32 | 1 | Target-version string length |
| 33 | 64 | ASCII version string, zero-padded |
| 97 | 7 | Fresh STREAM nonce prefix |

Each call generates a fresh 256-bit key and transaction ID from OS entropy.
There is no public sealing interface that accepts/reuses a previous key.
The key has no Debug/Clone/serialization implementation and is zeroized on drop.
Target version and exact length must come from a trusted transaction, not from
the untrusted capsule header. Invalid context is rejected before copying it or
allocating a spool. Zero-length and over-128-MiB plaintext are rejected.

Frames contain at most 65,536 plaintext bytes plus a 16-byte tag. Even exact
multiples of the chunk size have an authenticated final frame. Every stream
uses one preallocated 65,552-byte buffer, cleared between frames and on drop.
No growing whole-message buffer or decompression is used by the capsule layer.
This bound is for the crypto buffer, not a claim about whole-process peak RSS.

Decryption checks trusted context, all tags, final-frame state and exact EOF.
It writes into an owner-only rootfs `O_TMPFILE|O_EXCL` file: no directory entry
exists even before the first write, and the descriptor cannot be linked later.
Only after full authentication/fsync/rewind does it
return a read-only `Read + Seek` descriptor wrapper. It exposes no filename or
write API. Errors and process termination cannot leave a named partial plaintext
spool. A failed output/flush does not return a usable restore secret.

Replay protection is deliberately not claimed by encryption: it belongs to the
durable protected ticket state machine below. AEAD also does not validate an
archive's filenames, entry types, modes or account semantics.

## Restore archive v1 (implemented capture/validation)

`restore_archive.rs` consumes authenticated private plaintext, not a pathname
that a USB host can replace. It retains that descriptor and exposes an immutable
member index plus bounded copying of an indexed file. It does **not** unpack or
write any live destination. Capture also returns a private anonymous descriptor.

The uncompressed USTAR format starts with `restore-format`, containing exactly
`nanokvm-restore-v1\n`. Only regular-file entries are admitted:

- `files/<canonical-relative-path>` carries an allowlisted setting.
- `absent/<canonical-relative-path>` is an empty record for a closed set of
  presence-controlled flags. Exactly one write/absence record is mandatory for
  each such path; it is not a general delete operation and cannot delete trust
  or identity files.

The schema in `restore_policy.rs` selects account state, SSH host identity and
existing root SSH client configuration/keys, network/firewall/DNS/time/syslog,
TLS/session settings, AP credentials and video preferences, HID/USB settings,
and recognized optional-app configuration/state. These are sensitive local
operator data, encrypted by the capsule, never release assets or logs. Required
identity files must be present and nonempty. At the structural archive layer,
presence of `session_secret` or
`server.yaml` is a structural minimum, **not** semantic validation of effective
authentication configuration; the separate app-identity layer below is required.

Boot disk enablement is represented by an empty `boot/usb.disk0` record. Its old
contents can never become a restored raw/custom LUN backing path. A missing flag
is explicit, so an image default cannot silently re-enable a disabled function.

Rootfs executables, init code, update trust, legacy markers, caches and generated
Picoclaw control profile/skill are excluded. User script uploads and Picoclaw
workspace data are retained with mode `0600`, without execute/set-ID bits; their
contents are not asserted to be harmless. Nothing in this layer executes them.
The terminal capability gate, disabled historical autostart behavior and Pico
local-host privilege boundary remain mandatory WP-10/WP-15 integration gates.
Unsupported state under a selected tree aborts capture rather than being silently
dropped (except the explicitly regenerated control profile/skill).

Limits are 128 MiB total, 32 MiB per file, 4,096 file/absence records, 240-byte
paths and 16 components; directory scanning has a separate bounded entry budget.
Validation rejects traversal, aliases, duplicates, ancestor/file conflicts,
links, devices, FIFOs, sparse/GNU/PAX extensions, unexpected owners/modes, hidden
concatenated archives, nonzero padding and missing two-block trailers. Raw tar
iteration rejects extension types before reading their potentially huge bodies.
No decompression or whole-archive allocation is used.

Source directories and private staging are pinned by file descriptors. Exact
locked `rustix 1.1.4` safe APIs use Linux `openat2` with `BENEATH`, `NO_SYMLINKS`
and `NO_MAGICLINKS`; member lookup also requires `NO_XDEV`. `/boot` is the one
separately pinned source mount; nested mounts and bind aliases are rejected.
Private staging must stay on rootfs, owner-only `0700`, owned by the effective
user. Files must be regular, single-link and match the captured inode/size/
timestamps before and after a bounded copy. This does not replace stopping all
writers: coherent multi-file state remains the caller's responsibility.

There is no weaker pathname/named-temp fallback if `openat2` or `O_TMPFILE` is
unsupported. Their successful execution on the actual vendor kernel/ext4, free
space and I/O failure behavior are still target acceptance requirements.

## Canonical app identity (implemented, not connected to raw writer)

`restore_identity::capture_effective` requires the running `Config::load()`
result, its actual logical cwd and the exact active config path (including a
custom `NANOKVM_CONFIG`). It reads the latest persisted config with pinned,
bounded source I/O instead of serializing the immutable startup preferences.
Legacy key/media aliases are normalized by the same pure Config helper.

The current account path and effective embedded/file-backed session key must
agree with the running identity. Pending account-path or key changes fail
preflight and require the ordinary server restart first; there is no default
account, secret generation or stale-config fallback. Account JSON and supported
Argon2/bcrypt hash syntax are checked without a password, expensive hashing or
rehashing. Existing account bytes/hashes are retained unchanged.

Custom protected rootfs account, config and TLS sources are captured into fixed
`/etc/kvm/{pwd,server.yaml,session_secret,server.crt,server.key}` destinations.
The effective key is embedded verbatim, including meaningful whitespace, and
the canonical session file must contain that same value plus a newline. All
secret-bearing output files are `0600`. Stale unused default copies never win
over the actual custom source. The source files are not modified or migrated
in place by this operation.

All known Rust Config fields are retained except these fixed paths and the
redundant legacy key alias. In particular, unchanged persisted HTTP stays HTTP:
there is no forced HTTPS conversion or certificate generation. Latest explicitly
persisted TLS/protocol preferences are the requested next-boot state and may
differ from the running listener; a complete matching certificate/key pair is
validated with the same rustls provider before accepting it. This is not proof
of the certificate loaded in RAM by the current listener. HTTP without any TLS
pair is valid; a partial or broken pair is rejected instead of silently dropped.

Unknown top-level or nested YAML fields are not silently discarded. A separate
restore-only closed-schema streaming pass checks every Config section after
normal typed parsing; unsupported extensions require explicit migration before
capture, without changing their source file. The same check runs after capsule
authentication. All existing fields and legacy aliases remain supported, along
with normal partial defaults, comments and anchors over known fields. Merge keys
are unsupported rather than silently ignored. The 64-KiB input budget is checked
before parsing; no generic YAML value tree is built by the inventory pass and
errors do not echo input. Normal runtime Config parsing is unchanged. A new
Config field requires explicit restore inventory review, not automatic omission.

Non-default web/media/update-cache/trust layouts fail with an explicit migration
requirement. Source traversal, symlinks, mount aliases, missing/invalid identity
and oversized data also fail before snapshot output. Limits: config/key 64 KiB,
account/secret 16 KiB, certificate chain 256 KiB. Owned sensitive buffers and
parsed key/credential strings are zeroized on drop; parser errors never echo
their input. This does not claim complete third-party parser memory erasure.

After AEAD and structural archive validation, `check_identity` checks canonical
paths, account/hash syntax, exact key/file consistency, bounded sizes and TLS
again, returning a private `IdentityCheckedRestore`. It also requires the native
account checks and the SSH configuration-path guard below. It does not authenticate
a ticket, prove full SSH policy/key validity, apply files or stop provisioning.
In-memory web sessions are not restored across reboot.

References checked for the implementation:

- [RustCrypto ChaCha20Poly1305 0.10.1](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/)
- [RustCrypto STREAM implementation at aead-v0.5.2](https://github.com/RustCrypto/traits/blob/aead-v0.5.2/aead/src/stream.rs)

## Native account preflight (implemented, SSH/runtime gates still open)

Capture and authenticated validation now require native `AccountFiles` from the
exact verified immutable signed target rootfs. This carrier does not verify its
origin. A pre-fakeroot Buildroot `target/` directory is not a valid substitute:
package users, including OpenSSH's dynamically assigned sshd user, can be added
only during final image assembly. Current Picoclaw has no fixed service UID;
its future dedicated account must be defined by signed packaging, not invented
or allocated by the restore helper.

`restore_native` parses passwd/group/shadow and optional gshadow with 64-KiB
per-table, 512-line and 4096-byte line limits. Names/UIDs/GIDs are unique,
primary groups and supplementary members must exist, passwd/shadow entries
correspond, and gshadow membership must agree with group. Controls, malformed
rows, inline passwd/group hashes, empty native user passwords, duplicate IDs,
extra UID 0 and unsupported root layout require an explicit migration.

Root remains UID/GID 0 with `/root` and a recognized shell. Existing password
rows, expiry fields, account locks and root shell are preserved, never replaced
with image defaults, unlocked, regenerated or rehashed. New signed-image users
must have unused nonzero UID/GID, a locked password and non-login shell. Common
users must retain UID/GID; non-root service home/shell and a required locked state
cannot silently disagree with the image. Conflicts stop capture rather than
renumbering existing files or changing account policy behind the operator's back.

Existing group membership is retained and extended by exact signed-image member
requirements in stable order. gshadow retains existing password/admin state and
synchronizes membership; a new common-group admin requirement needs explicit
migration. Output is revalidated as a whole. Authenticated validation requires an
already complete, idempotent merged result; it cannot silently repair a capsule
that omitted required signed service identities. Native capture uses these exact
bounded snapshots as archive replacements instead of rereading their source.

Unlocked native hash syntax/parameters are checked against the pinned target's
musl 1.2.6 crypt implementation: DES/BSD-DES, MD5, SHA-256/SHA-512 and bcrypt
2a/2b/2x/2y. This is preservation compatibility, not a recommendation to generate
weak legacy hashes. SHA rounds are 1000..9,999,999; bcrypt cost 4..19, matching
the pinned implementation's bounds. Encoded lengths and unused bits must be
canonical. Literal shadow-safe salt punctuation, spaces and UTF-8 are retained.
Noncanonical SHA rounds are rejected: musl rewrites that prefix and OpenSSH uses
exact stored/result comparison. Locked `!`/`*` suffixes stay opaque and locked.
No password is supplied, calculated or verified by this preflight. Owned table
buffers and decoded bcrypt bytes are bounded/zeroizing; errors do not echo data.

The isolated writer/helper must still prove signature/image binding, executable
availability and ownership for preserved shells/service homes, source quiescence,
and the actual linked crypt provider. In particular, accepting a recognized
`/bin/bash` source shell does not prove bash is installed in the new image.
Custom non-root homes/SSH state outside the fixed archive allowlist require an
explicit verified preservation/reinstall or migration gate; keeping only their
passwd/shadow rows is not a promise to preserve their files.
SSH host keys/config/includes, actual `sshd -t`/effective root-password policy,
and login after restore remain mandatory separate checks. No native-table test
proves SSH availability or complete C1 closure.

## SSH configuration-path guard (implemented, not full SSH acceptance)

`restore_ssh` checks a bounded immutable snapshot before archive creation and
rechecks authenticated archive contents before returning `IdentityCheckedRestore`.
The closed directive/alias inventory matches the pinned OpenSSH 10.5p1 parser;
unknown directives require explicit verified migration. Its lexical guard follows
the pinned keyword/argument splitting rules, including quotes, escapes, equals
and token-start comments. It is not a replacement sshd syntax parser.

Host keys/certificates, root authorized-key files, banner, CA, revocation,
principals and host-based trust data are restricted to purpose-specific fixed
protected destinations. A banner cannot refer to another captured secret such
as a host private key or the session secret. Includes are limited to flat
`/etc/ssh/sshd_config.d/*.conf`-style patterns or their `sshd_config.d/` relative
equivalents. Every captured server `.d` file and every Match branch is checked,
even if currently unselected. This deliberately preserves latent operator state
without allowing an unchecked branch to become active later; it does not resolve
the real Include graph, cycles, selected options or Match connection semantics.

Mutable external helpers, host-key agents, chroots and security-key providers
are not imported as executable authority. The initial policy permits disabled
command hooks/agents/chroot, the internal provider, fixed signed-image SSH
session/auth/xauth/sftp paths and constrained internal-sftp commands. PAM and
PermitUserEnvironment must stay disabled for this pinned layout. Existing
`sshrc`, root `.ssh/rc` or `.ssh/environment` requires explicit migration, not
silent deletion or automatic activation. Valid custom key/trust/helper layouts
outside this schema also stop preflight; they are not silently rewritten.

The snapshot owns the exact checked bytes and records absence of all selected
fixed SSH files. It also pins both SSH enablement flags. Canonical archive capture
uses these replacements and the completed `.d` inventory, never a second live
tree scan. A file appearing after preflight cannot be imported unchecked, and
later flag changes cannot silently enable a keyless snapshot. Optional empty
authorized-key/trust/banner/config files remain representable. Enabled SSH needs
at least one nonempty selected host-key file; disabled SSH may remain keyless.
This is a presence check only, not key parsing or proof of the selected key.

Budgets: 128 present snapshot files, 64 KiB per config/private host key, 512 KiB
total config, 4 MiB per other data file, 8 MiB total selected data, 8192-byte
lines, 64-byte keywords and 128 arguments per line. Owned config/key bytes are
zeroizing, errors do not echo their input, and the guard never executes helpers,
loads a provider, opens an arbitrary configured path or connects to an agent.
The caller must still quiesce all writers under the common transaction lock.

Mandatory remaining preflight: actual signed sshd `-t`/`-T` with a safe isolated
snapshot, Include resolution, effective root-password/authentication policy,
host-key/public-key/certificate parsing and matching, authorized_keys/principals
options (including command/environment effects), SetEnv/AcceptEnv session effects,
signed executable/library provenance and complete custom-user-home handling.
Client SSH config/keys remain operator data, not authority to execute them during
restore. Follow with actual preserved-identity login and disabled/start-once
runtime tests. The synthetic host-key fixtures used here intentionally do not
claim cryptographic key validity. No host test establishes target SSH acceptance.

### Native private-key possession probe

`IdentityCheckedRestore::check_native_host_keys` is a separate asynchronous
preflight over the already-authenticated immutable archive. It checks every
preserved RSA/ECDSA/Ed25519 private host key and any public companion, without
regenerating or changing their bytes. Orphan public files, empty/invalid private
keys, wrong algorithms and mismatched companions stop preflight. Disabled SSH
may stay keyless; any private key it does retain is still checked.

OpenSSH `ssh-keygen -y` extracts stored public fields; it does not universally
prove their mathematical agreement with private components. The pinned Ed25519
deserializer, for example, does not derive its public key from the seed. Likewise,
`sshd -t` public/private comparison is not a signature-possession test. The probe
therefore also signs a fresh 32-byte synthetic challenge and verifies it through
OpenSSH SSHSIG with a fixed namespace/principal and an exact allowed-signers
record built from the selected public identity. This uses OpenSSH cryptography,
not a custom signature scheme. A regression changes only an Ed25519 seed while
retaining its stored public fields: `-y` passes, but the possession probe fails.

Only fixed `/usr/bin/ssh-keygen` is executed, never a shell or configured hook.
Its environment is scrubbed, including SSH_AUTH_SOCK and loader/provider variables;
an agent cannot supply the signature instead of the private file. The key,
signature and allowed-signers inputs use anonymous private rootfs descriptors
exposed through the live parent's `/proc/<pid>/fd/<n>`, with no named plaintext
files. No key bytes enter argv/environment or diagnostic output. Output buffers
are zeroizing and capped at 16 KiB; stdin/stdout/exit share an eight-second
per-child deadline, followed by bounded kill/reap on failure. Cancellation kills
the single child and leaves no detached pipe-reader task.

This method is not implicitly run by synchronous capture or `check_identity`.
The isolated writer/early helper must require it before applying/writing state,
inside the exact verified target runtime with trusted executable/libraries,
private staging, caller-held update serialization and a working protected
proc-fd view. Current host tests use native host OpenSSH and prove this component,
not target provenance, target timing/RAM, certificate policy, full sshd semantics
or actual login. No production writer/boot integration is implied.

### Exact ROOTFS readonly view (component; production integration open)

`restore_rootfs::RootfsView` consumes a ROOTFS `ImageReader` from the one-shot
descriptor channel. The trusted transaction must first authenticate the archive
and close every writable snapshot alias; the transport and this view do not
verify signatures or authorize restoration. BOOT/ROOTFS role selection remains
the trusted caller's responsibility. No mutable `target/` tree or p3 ELF is used
as a substitute for the exact final, packaged ROOTFS bytes.

This is a fresh, single-threaded, privileged-child API, never a live-server call.
It checks the real parent around a parent-death SIGKILL lease, creates private
mount/network namespaces, makes mount propagation private and verifies procfs.
The caller supplies a root-owned, private, empty mountpoint on the current rootfs
and must protect its ancestors, hold the transaction lock, enforce a wall timeout
and exit the child after failure. The guard is not Send/Sync. It does not yet
remove capabilities or close inherited vendor FDs: those belong to the separate
native-execution boundary and must precede any target executable.

The narrow loop adapter uses generated `linux-raw-sys = 0.12.1` UAPI definitions
(already locked transitively; now a direct exact dependency, Apache/MIT-compatible)
and the pinned nix ioctl feature. The isolated unsafe ioctl boundary is required
for Linux loop hardware control, not for performance. All pointer objects are
initialized exact ABI types with owned live descriptors and documented safety
invariants. No hand-written ABI layout, shell, losetup command or named backing
path is accepted. Source checks require a positive 512-aligned size from 4 KiB
through 2 GiB, regular anonymous nlink-0 inode, exact length/current owner, safe
mode, kernel O_RDONLY and CLOEXEC.

Only checked root-owned `/dev/loop-control` (char 10:237) and `/dev/loopN` (block
7:N), without symlinks/nested mounts, are opened. Setid/sticky/world-writable
device nodes are rejected; standard privileged group-device permissions are
not treated as an unprivileged-user isolation boundary. Atomic `LOOP_CONFIGURE`
sets READ_ONLY|AUTOCLEAR, zero offset, exact size limit and no PARTSCAN/encryption.
An EBUSY selection race permits at most eight attempts. Before mounting, kernel
status must match backing device/inode, size/offset/number/exact flags, no
encryption; BLKROGET and BLKGETSIZE64 must confirm readonly/exact byte size.
Unsupported ioctl, absent device nodes or unexpected flags fail before writes.
Kernel `loop.max_part` can force PARTSCAN during configure, before status is
checked. The adapter therefore first opens actual sysfs and the fixed
`module/loop/parameters/max_part` path, with no symlinks or crossed mounts. It
requires a root-owned single-link regular mode-0444 parameter containing exactly
`0\n` and EOF, using at most three bytes of bounded input. This check precedes
even loop-control/device opens and GET_FREE; it does not change a global kernel
setting. Missing/nonzero/malformed parameters, fake filesystem roots and even
same-filesystem bind replacements fail closed. Successful target loop operation
and absence of partition scanning still need runtime acceptance.

The view mounts ext4 with `ro,nodev,nosuid,noexec,noload`; journal replay and native
execution are not allowed. Reopening must identify exactly the loop device,
ext4 superblock type and all four mount flags. Fixed passwd/group/shadow and
optional gshadow are read through no-symlink/no-cross-mount descriptors, bounded
to 64 KiB each, root-owned safe single-link regular files, into zeroizing buffers;
the existing cross-file native-account validator is mandatory. Preserved root
home/shell are checked against this image: real safe root home and regular safe
shell, both with owner-execute/search permission, with shell symlinks resolved
only under openat2 IN_ROOT|NO_MAGICLINKS|
NO_XDEV. This metadata check is not password-login or ELF/interpreter validation.

Drop lazy-detaches the exact pinned mount, then closes mount/loop/backing refs;
AUTOCLEAR and fresh-child namespace teardown are the cleanup mechanisms. It never
issues LOOP_CLR_FD against a potentially reused device and never cleans unrelated
loops. Actual cleanup after a successful mount or process kill remains a runtime
gate. The retained RC12 kernel build config has LOOP=y (eight initial devices),
EXT4_FS/DEVTMPFS/PROC_FS and mount/network namespace support; this is build evidence,
not a current-device `/proc/config.gz` observation. This WSL has no loop-control
or loop nodes: successful LOOP_CONFIGURE/ext4 mount/AUTOCLEAR are NOT host-tested.

Host tests cover generated ABI/request framing, readonly/anonymous/size/mode/
CLOEXEC guards, status mutations and real ENOTTY on regular files, plus bounded
account/layout/shell containment cases as mapped root in disposable userns
children. The helper asserts that exactly one requested nested test executed,
preventing a zero-test filter false pass. No real host account files are copied.
Exact raw.12 target mount, vendor/exFAT behavior, target sshd/key-possession/
effective-policy checks and production writer/early-restore use remain open.
The existing system API now refuses raw installation until the replacement
writer is composed; this component does NOT close C1 or make a releasable raw update.

### Exact-image SSH runtime binding (component; caller integration open)

`exec_sshd_syntax_from_image` consumes a `RootfsView`, separately from the generic
prepared-runtime entry below. The same bounded no-symlink/no-special-file/
no-hardlink/no-cross-mount validator inspects the private identity root BEFORE
image imports. Existing executable trees or loader-path overrides cannot be
hidden under bind mounts. Prepared native account tables must validate against
the exact image's service users, and preserved root home/shell must exist there;
no factory password substitution, account normalization or live `/etc` fallback.

After the sandbox unshares again, it reopens the image mount in that namespace
and requires the exact pinned root inode/device, retained loop device, ext4 type
and readonly/nosuid/nodev/noexec flags. Fixed imports are `usr`, `lib`, `bin`,
optional `sbin`/`lib64`, `etc/ssl`, `var/empty`, and the two known RV64 musl path
files. Source symlinks resolve only IN_ROOT|NO_MAGICLINKS|NO_XDEV. Whole signed
runtime directories preserve library, loader, provider and internal-link layout;
host `ldd`, a mutable Buildroot target tree or a guessed library closure cannot
establish production provenance. Directory contents derive authority from the
authenticated immutable image, not recursive per-file policy validation.

Targets are absent or safe empty private placeholders. After each fixed bind,
the new mount is reopened and inode/device matched before remounting the clone
readonly/nodev/nosuid. Code imports become executable; config/empty imports stay
noexec. The original image remains noexec. Generic tree validation is not relaxed
to admit uploaded symlinks or arbitrary preexisting mounts. The same root pivot,
capability removal, inherited-FD closure, limits and seccomp boundary then apply.
All owned image/loop/setup descriptors close before native execution; imported
mount clones retain filesystem references until child exit. Actual successful
loop AUTOCLEAR with those clones, including kill/failure teardown, is NOT tested
by the host bind fixtures and remains a mandatory target gate.

The static `nanokvm-ssh-sandbox` also accepts a fixed image mode: append
`--image-root EMPTY_PRIVATE_MOUNTPOINT --transaction HEX32 --version VERSION
--boot-size BYTES --rootfs-size BYTES` after the legacy arguments. Its only image
input is the private stdin SEQPACKET channel above, duplicated CLOEXEC with the
original stdin redirected to `/dev/null`. Expected context/peer/descriptors must
match before privileged image setup; BOOT is closed unused, ROOTFS enters the
readonly view. Parent-death lease is installed before receive. No mutable image
pathname, arbitrary command, arbitrary FD number or secret CLI input is accepted.
Public transaction context is NOT a signature. The trusted parent still must
authenticate both immutable snapshots, close writable/Command aliases, build
protected identity staging, hold the common lock and bound wall time/kill/reap.
The blocking supervisor below invokes this mode as a component; the production
system API and release packaging do not yet invoke it.

Feature-gated host fixtures bind a synthetic readonly/noexec source and exercise
the same import/pivot/native boundary, including actual host sshd valid/invalid
syntax, internal links, readonly denial and config noexec. They intentionally
bypass image signature/loop/account provenance and are excluded from the static
release helper. A real exec test rejects a mismatched transaction before any
privileged setup. These tests do not prove target ELF compatibility, SSH login,
exact raw.12 mounting, isolated writing or early restore.

### Private authenticated SSH identity-root builder (component)

`restore_preflight::prepare_sshd_root` accepts only `IdentityCheckedRestore`, not
an arbitrary archive/path tree. It plans all selected inputs before creation:
account tables, bounded hostname/hosts, and the same closed inert server-SSH
subset used by the authority guard. Client private keys/config, app credentials,
scripts, workspaces, enablement flags and executable/runtime files are omitted.
The private root is for syntax preflight, not the full restored system. Missing
optional inputs stay absent; no factory account/key/password is synthesized.

The caller provides an empty root-owned mode-0700 directory on `/`, without
symlink or crossed-mount components. Fixed directories and regular files are
created descriptor-relatively with EXCL, fixed owner/group 0 and safe modes.
Limits are 140 selected files / 9 MiB total; hostname/hosts each have a 64 KiB cap.
Native account and SSH-specific limits already hold in the checked identity.
The only generated configuration is files-only NSS for isolated local account/
host lookup; no ambient host NSS configuration is copied. Runtime code still
comes exclusively from the separate exact-image binds above.

`PreparedSshRoot` owns the exact created inventory and pinned directory. Its
checked path must be revalidated before helper invocation. The production job
must retain this guard until the child is reaped, then explicitly check cleanup.
Cleanup pins each parent without links/mounts, compares the final inode/device
and unlinks only recorded entries, never a replacement or unknown tree. An error
is a hard cleanup failure, not successful removal or a reason for broad rm-rf;
Drop is best effort. Caller must hold the common lock and exclude concurrent
writers/protect ancestors; hostile local root is not contained by this API.

These are ephemeral named native-input files on private rootfs, not a named
plaintext archive spool, boot marker or durable restore commit. After abrupt
process/power loss, any residual private directory cannot authorize apply; exact
transaction-owned crash cleanup is still required in the future orchestrator.
The builder does not itself prove native key possession/effective SSH policy,
signature/ticket authorization, or successful restoration. No production system
API currently invokes it. Host tests authenticate a synthetic capsule, build this
root, import the host runtime through the same image fixture boundary, and run
real sshd syntax successfully; target loop/image provenance is intentionally not
claimed. Kernel EFBIG after copied native tables verifies partial-input cleanup.

### Private effective SSH policy (component; system-API integration open)

The image-only helper mode may append `--effective-root FIXED_ROOT_CONNECTION_SPEC`.
It executes only the signed `/usr/sbin/sshd -e -T -f /etc/ssh/sshd_config -C SPEC`,
inside the same root/caps/FD/seccomp boundary. Legacy pathname-only mode cannot
select it. SPEC is a bounded fixed root-user profile: host, numeric peer/local
addresses, nonzero local port and optional rdomain. No other username, command,
extra connection key or environment is accepted. `Match version` uses sshd's own
compiled version, not an invented `-C version=` key. This contract was checked
against pinned [OpenSSH 10.5p1 source](https://github.com/openssh/openssh-portable/blob/V_10_5_P1/servconf.c).

Native stdin/stderr stay `/dev/null`; effective stdout must be an owned root-owned,
blocking write-only anonymous PIPEFS descriptor above stdio, CLOEXEC until its
final dup2 into stdout. Files, read ends, nonblocking pipes and ttys are rejected.
This checks descriptor shape, not reader confidentiality:
the trusted parent still must own a private reader and close unrelated aliases.
No native output may be routed through ordinary Longrun/application diagnostics.

`restore_effective::read_policy` reads at most 64 KiB + one overflow byte and
512 lines, requires complete newline framing and exactly one occurrence of each
selected field (case-insensitive). Missing/duplicate fields, invalid booleans,
numbers/root-login values, NUL/CR, malformed startup triples or overflow fail.
It returns an immutable typed auth/rate summary, never the raw dump. Raw buffers
and opaque method suffixes are zeroizing; error messages contain no input bytes.
Authentication-method suffixes/chain counts follow the native formatter rather
than a narrower invented syntax; the total output budget remains enforced.

The private comparison binds the WHOLE raw native dump and canonical context,
including unknown fields and repeated arrays. It is not a comparison of only
the summary. The caller must bind both results to the same exact verified native
runtime; the parser does not authenticate an executable/version/image hash or
make cross-version equivalence claims. One context covers only its Match branch,
not every possible connection, authentication factor, authorized-key condition
or successful root password login. No login policy is force-enabled.

Before accepting a result the parent must concurrently drain the private pipe,
enforce a wall deadline, kill/reap on cancellation/overflow/error, and require
native success plus EOF. The reader's byte cap is NOT a time bound. Production
system-API integration, isolated key-possession integration, the complete Match
matrix and real target login remain required. Host tests exercise repeated equal
contexts, a differing Match Address branch and invalid output descriptor modes;
they do not substitute for signed-image/loop/target acceptance.

### Owned blocking SSH preflight supervisor (component; system API not wired)

`restore_job::SshPreflightJob` connects the typed private identity root, the two
readonly image descriptors, public transfer context and fixed syntax/effective
helper mode. It consumes its inputs and keeps the identity guard until the
direct child has exited and been reaped. One fixed small SCM_RIGHTS packet is
queued before spawn, then the sender and transfer aliases close; original
readonly image descriptors remain owned for sequential key-proof children.
A failed spawn drops the receiver/queued descriptors. The configured Command is dropped
immediately after spawn so it cannot retain stdin/stdio aliases. A successful
send remains only a queued transport record, not native acceptance or authority.

`PinnedSshHelper::capture` copies at most 32 MiB through a 64-KiB buffer into
rootfs-only anonymous O_TMPFILE storage, checking exact size/EOF and SHA-256.
**The expected size/hash must come from trusted build/release authority, not p3
or the helper's own manifest.** This crate-private constructor is not signature
verification; the public build-bound constructor is described below. It requires
ELF64, little-endian RV64 ET_EXEC, a bounded program-header table and a LOAD,
with no PT_INTERP/PT_DYNAMIC, and bounded/congruent LOAD ranges. This admits the
current static build, not an unreviewed future static-PIE layout. No ambient
loader/vendor library is used.
After fsync/chmod0500 it independently reopens the exact anonymous inode as
O_RDONLY/CLOEXEC, closes the only writable owner, and pins the descriptor above
stdio. Exec uses actual procfs `/proc/self/fd/N`, never the mutable source path.
Source replacement/overwrite after capture cannot change executed bytes; this
does not contain hostile local root or raw backing-store writes.

Native stdout is always a newly created private pipe, stderr is null. The parent
drains nonblocking while checking child status, cancellation and a 15-second
helper-execution deadline (not a whole transaction/capture deadline). Effective
output has a strict 64-KiB cap; syntax mode rejects any output. Native exit zero
AND output EOF are required, followed by the existing zeroizing parser for
effective mode. Raw output never enters ordinary logs/errors/results. Cancellation
uses a caller-owned AtomicBool with SeqCst loads/stores, checked at most every
20 ms while waiting, after bounded reads and again after checked cleanup. The
pre-spawn transport has its separate two-second socket timeout.

Every child-owning error/unwind path kills and synchronously waits before the
root can drop. Ordinary Result paths then explicitly check exact-inventory
cleanup, and cleanup failure overrides a successful native result. Unwind has
only best-effort root Drop; it returns no outcome. Persistent kernel wait/I/O
failure may prevent completion: ownership is retained instead of abandoning a
live reader or claiming a finite reap guarantee. Unexpected recovery entries are
preserved, not recursively deleted. Abrupt process/power loss still needs the
future protected transaction-owned crash cleanup; residual files grant no apply
authority.

This API is synchronous and creates no async/detached worker. Its caller must
run it on the dedicated blocking transaction owner, retain the common lock and
quiesced writers, signal cancellation and join that owner. Dropping a Tokio
spawn_blocking JoinHandle does not cancel it and is not a valid integration.
The native sandbox cannot fork; this supervisor is not a process-tree manager
for arbitrary untrusted programs. Host lifecycle tests use explicit unit-only
host-ELF bypasses, not production provenance. They cover size/hash/ELF rejection,
source mutation/proc-fd exec, exact output bounds, cancellation, timeout, reaping,
zero exit without EOF, and real typed-root cleanup including unknown-file
preservation. Capturing the retained static RV64 helper does not execute it on
the host. Target loop/exec/kernel cleanup, protected backend authority, full Match
matrix and actual SSH login remain open. Production raw writing/early apply are
not integrated; the legacy path is retired with a temporary install barrier:
**C1 remains OPEN**.

### Signed image account export (component; capture not wired)

`capture_effective` needs the account tables of the exact target ROOTFS image.
`restore_job::export_signed_accounts` gets them from the same pinned sandbox:
`--export-accounts --parent-pid PID --image-root EMPTY_PRIVATE_MOUNTPOINT` plus
the public transfer context. The child receives both read-only image
descriptors, drops BOOT, mounts ROOTFS through `RootfsView::mount` (private
mount and network namespaces, read-only loop, `noload`), reads passwd, group,
shadow and optional gshadow with the existing checks and writes one
`restore_accounts` frame to its private stdout pipe. It executes nothing from
the image. The frame is `NKACCT01`, four little-endian lengths (`u32::MAX` only
for an absent gshadow) and the tables; each table is at most 64 KiB. The parent
reads it through the same supervisor (15-second deadline, cancellation, output
cap, exit zero and EOF), then requires the exact total length and
`restore_native::validate`. The frame proves neither the image nor a restore
authorization: the caller must already have authenticated both images. Host
tests cover the framing, the helper's fixed argument form and the parent with
host shell helpers; mounting a real image needs the target or root.

### Static helper build/package binding (component; app-slot authority open)

The linked build wrapper builds the helper first, without `linked-libkvm` and
with `NANOKVM_SSH_RUNTIME_BINDING` unset, in a separate Cargo target directory.
The build tool prepares a content-addressed envelope with eight-byte `NKSSHRT1`,
little-endian u64 image size, 32-byte SHA-256, then exact static-helper bytes.
The helper is bounded to 32 MiB; malformed/truncated/trailing framing and wrong
hash/ELF fail closed. No new signature format, key or trust-policy ID is added.

The backend build script requires and validates that complete envelope for a
linked RV64 build, then embeds a build-owned copy, not a runtime source path.
The linked device backend checks it at startup, retaining the exact bytes even
with LTO/strip. `PinnedSshHelper::embedded` validates its own build bytes and
passes them to the existing exact anonymous-file capture. It accepts only the
private rootfs spool directory, never a caller-selected helper/hash/path.
Generic host/helper builds have an empty envelope unless explicitly bound at
build time; the build-bound constructor fails closed when absent.

Host packaging inspects the copied backend without executing RV64 code. It
requires exactly one valid envelope, bounds the backend to 128 MiB and marker
candidates to 64, and records embedded helper hash/size in the app manifest.
Buildroot repeats inspection before installation and after the post-build Rust
ELF restore, with byte comparisons of source/active/backup backend copies.
The Python gate and shared Rust build/runtime parser reject foreign/dynamic
ELF, invalid program tables and out-of-image/overflowing/misaligned LOAD ranges.
These are consistency checks: an arbitrary hostile backend can append a valid
envelope, so packaging alone does **not** authenticate backend provenance.

The build input and backend must remain inside the trusted build/release and
protected app-slot boundary. A root-owned directory on writable/exported p3 is
not sufficient authority. Signed app provenance, protected app slots, production
transaction lock/quiescence/cancellation owner, retained writer/ticket and early
restore integration remain required. No system API has been switched to this
constructor yet; no raw partition write, loop/target/native-login or release
acceptance is implied. Synthetic host envelopes test framing/packaging only.

### Isolated native host-key possession (component; target acceptance open)

`Check::HostKeys` runs the fixed `--host-key-proof STAGE:ALGORITHM` image-only
helper mode for every staged RSA/ECDSA/Ed25519 private host key. Only the nine
public/sign/verify selectors are accepted; no custom key path, command, FD or
challenge/key bytes can be supplied through CLI. The original immutable images
stay owned for all children, and every child uses the same exact-image import,
private root pivot, zero capabilities, no-new-privileges, limits and seccomp.
No syscall/network/fork allowance was added for key operations.

The parent generates one fresh 32-byte OS-random challenge and creates a fixed
root-owned0600 file under the private root's `/run`. For each present key:

1. Native `ssh-keygen -y -P '' -f FIXED_PRIVATE_PATH` yields a bounded public
   identity; an existing public companion must match its decoded key/type.
2. Native `ssh-keygen -Y sign -q -n hardened-nanokvm-restore-key-proof-v1 -P ''
   -f FIXED_PRIVATE_PATH` signs stdin and emits its signature only on stdout.
3. The parent materializes that bounded signature and a generated single exact
   `restore-probe KEY_TYPE BASE64_KEY` allowed-signers entry at fixed per-key
   paths. Native `ssh-keygen -Y verify -q` checks the same challenge, namespace,
   principal, signature and exact allowed public key.

Sign/verify stdin is opened **after pivot** from the fixed challenge path inside
the readonly root. Its owner/type/single-link/mode/32-byte shape is checked. No
parent procfs, writable file, outside-root FD or live input writer is exposed.
Public extraction receives `/dev/null`. All native stderr stays null; public/
signature stdout is private, zeroizing and capped at16KiB, with native-zero/EOF
and the existing15s per-child deadline/kill/reap. Verify requires empty stdout.
The full proof is at most nine native children, not one15s whole-transaction
deadline; target storage/loop latency and peak space remain acceptance gates.
Environment is scrubbed, without SSH_AUTH_SOCK or provider/askpass options.
Encrypted/unusable keys fail explicitly; no password prompt, agent or factory
key-generation fallback is introduced.

The shared parser preserves native comments and public-companion compatibility:
it compares the first non-comment key identity, never copies comment strings
into allowed-signers. Pinned OpenSSH10.5p1 `do_print_public` prints arbitrary
stored comments, so enforcing exactly one output line would reject usable keys.
Cryptographic verify is bound to the exact reconstructed public key, not to
ignored trailing comment bytes. `-y` alone is NOT possession evidence. No-key
disabled SSH returns an explicit count0, not a login/enablement proof; enabled
SSH without a host-key candidate is rejected earlier by capture. Missing
optional `.pub` stays supported; no key/enablement is synthesized.

Namespace teardown removes bind mounts but not their underlying placeholder
inodes. The parent rejects every unowned runtime slot before spawn and, after
reap, records only the closed fixed set of newly created empty root-owned
directories/loader files. Existing receipts are rechecked for exact inode/device/
type/mode/emptiness before and after each child. These slots join the same
exact-inventory cleanup as identity/challenge/signature files. Replaced, nonempty
or unknown entries fail closed and are preserved, never recursively removed or
adopted as runtime/restore authority.

Host tests run the complete authenticated synthetic capsule -> typed builder ->
owned supervisor -> actual isolated host ssh-keygen public/sign/verify sequence
for all three algorithms, then verify that the root is empty. Missing/wrong
companions, an altered Ed25519 seed that still passes native `-y`, disabled
zero-key state, and unowned/replaced/nonempty/loader override cleanup are covered.
The host fixture explicitly bypasses signed target-image/helper provenance and
loop mounting; it is excluded from release builds. The older standalone
parent-proc-fd probe remains host diagnostics only, not target acceptance.
Production system-API/helper packaging/authority integration, actual RV64 native
execution, loop/clone/AUTOCLEAR/kill behavior, certificate/full Match/login gates,
writer/early apply/crash recovery and full release acceptance remain required.

### Fresh-process SSH syntax sandbox (component only)

`nanokvm-ssh-sandbox --root PRIVATE_PREPARED_ROOT --parent-pid PID` is a separate,
single-threaded privileged process, never a function to call in the live server.
It checks its real parent before/after installing a parent-death SIGKILL lease
and before native execution. The caller must additionally enforce a bounded
wall-clock deadline and kill/reap; the helper's CPU limit is not a wall timeout.

This component checks isolation, not authenticity. The future caller must bind
the exact signed target executable/loader/libraries and authenticated immutable
identity snapshot, materialize them into a quiesced private root on `/`, protect
that directory and its ancestors, and hold the transaction lock throughout.
The separate exact-image entry imports its runtime, and the builder above
prepares its identity inputs; their production system-API caller is still missing. A pathname,
private mode, ELF header or successful syntax exit never grants restore authority.

The root is owner-0 and private, with no setid/sticky bits; the bounded tree
rejects symlinks, special files, hard-linked regular files, writable group/world
modes and nested mounts. Limits are 1024 members, 64 MiB, depth 16, path 240 bytes.
`.oldroot`, `proc`, `sys` and `data` must be empty. `/dev/null` starts as an empty
regular placeholder. Fixed `usr/sbin/sshd` must be a regular executable. Signed
library symlinks must be resolved/materialized as checked regular files on this
prepared-root path, not copied as ambient path authority. Exact-image
binds use the separate provenance-checked entry; do not relax this generic
pathname-only tree validator to admit them. Hostile concurrent local root is
not a boundary this private-directory contract can contain.

Only mount and network namespaces are used. The retained target enables those
and seccomp, but not USER/PID/UTS/IPC namespaces or cgroups; no kernel change is
made or silently assumed. Mount propagation becomes private; `/dev/null` is
opened in the new namespace and bound read-only/nosuid/noexec; the new root is
recursively bound, reopened with exact inode/device comparison, pivoted, and the
old root detached. Root is then read-only/nodev/nosuid, with only the explicit
null child mount permitting a device. Host `/proc`, `/sys`, p3 and other mounts
are absent. All inherited fds above stdio become CLOEXEC; pinned outside root
fds are dropped; native stdio is replaced by `/dev/null` before exec.

All effective/permitted/inheritable, ambient and bounding capabilities are
removed. Locked no-root/no-setuid-fixup/no-ambient-raise securebits and
no-new-privileges prevent reacquisition despite retained UID 0. Hard resource
limits: core/file size 0, fd table 64, address space 128 MiB, CPU 10 seconds.
The native-architecture seccomp allowlist denies socket/connect, clone/fork,
signals, ptrace/process-vm access, namespaces/mounts and privilege changes.
`dup2`/`dup3` destinations are limited to stdio; `fcntl` admits only F_GETFD,
F_SETFD and F_GETFL, not signal ownership/leases/dnotify. Fixed harmless ioctl
queries, self prlimit and read-only prctl
queries are admitted alongside bounded-runtime file/memory/signal setup syscalls.
File writes remain impossible through the read-only root and closed
outside descriptors, not through an open-path string filter.

The one initial command is fixed: `/usr/sbin/sshd -e -t -f /etc/ssh/sshd_config`,
with a scrubbed environment and no native output forwarded or logged. Its exit
code is only a syntax result. Seccomp necessarily admits the initial `execve`;
it is not an executable-pathname filter and a compromised native process can
re-exec within the same closed root. This is not a general-purpose daemon,
connection/session or `Authorized*Command` sandbox. The separate image-only
effective mode/parser above is not a certificate/full Match matrix or
root-password availability proof.

Build this helper only through `server-rust/scripts/build-restore-runtime.sh`:
locked/offline static musl, no ELF interpreter, DT_NEEDED, RPATH or RUNPATH. The
default output is under `server-rust/target/restore-runtime/`, separate from an
ordinary Cargo build so a generic dynamic helper cannot overwrite that result.
The
regular linked vendor build now selects only backend/hwmon, avoiding an ambient
`/kvmapp/server/dl_lib` loader path for this privileged helper. The build host,
compiler/toolchain/environment still require release provenance/A-B acceptance;
these ELF checks are not signature or reproducibility verification. Protected
rootfs installation and packaging are not yet wired. Exact new dependency:
`seccompiler = 0.5.0` (Apache-2.0 OR BSD-3-Clause, locked checksum); no new unsafe.

Opt-in `sandbox-test-fixture` tests execute real host namespaces/seccomp, not a
mock: root/capability/bounding/fd/network/fork/signal restrictions, rejected
unsafe layouts, real host sshd valid/invalid config and invalid synthetic key.
Host userns only grants disposable fixture privilege and is not target evidence.
The fake native executable is excluded without the opt-in feature. Target
kernel execution, signed-runtime provenance and actual SSH login remain gates.
The previous possession-probe API uses a parent proc-fd view and remains host
diagnostics only. The isolated fixed key mode above does not reintroduce host
proc or outside input descriptors; target/system-API integration remains open.

## Protected boot ticket v1 (implemented, not wired into boot/writer)

`restore_capsule::ticket` is deliberately a child of the capsule module. It can
encode the private key into one fixed protected record without exposing a key
getter or general-purpose serialization. Tickets and secrets have no Debug,
Clone or serde implementation. p3 files/markers cannot be imported as tickets.

`Store::open_boot` is the production entry point. It requires root and pins the
whole `/dev/mmcblk0p1` vfat mount at `/boot`, checking the actual block device,
mountinfo, owner and private mode. The mount must be rw/nosuid/nodev/noexec with
fmask 0177/dmask 0077. Bind subtrees, duplicate mounts, symlinks, nested mounts,
shared permissions and a different device are rejected. A kernel exclusive
nonblocking flock on the pinned `.nanokvm-restore` directory serializes owners;
the restore job must own its lifetime, not an HTTP request future.
`Store::drop` explicitly unlocks before closing its private descriptor: CLOEXEC
does not prevent a sibling pre-exec child from momentarily inheriting the same
open file description and retaining its lock. `Store` is non-Clone and never
lends that descriptor; while a Store is live, concurrent owners still get Busy.

The 512-byte `state` record contains the transaction, source/new boot IDs,
device identity digest, exact encrypted capsule/boot image/rootfs image digests,
system/app versions, target, phase and active key. Reserved bytes/string padding
must be zero. The final SHA-256 detects corruption; it is **not** authentication.
Authorization comes from the private expected p1 store and verified caller
context. Device identity must come from stable hardware, not a cloned machine-id:
`ticket::device_id()` is SHA-256 over the fixed domain `nanokvm-restore-device-v1`
and the exact bytes of `/sys/class/cvi-base/base_uid`, the SoC unique-ID
attribute S95 also derives `/device_key` from. A missing, empty, oversized or
NUL-containing attribute is no binding. A kernel that prints it differently
makes the restore refuse; it never normalizes or guesses.

Publication creates the fixed `.state.next` with CREATE|EXCL, writes and fsyncs
the complete record, renames it to `state`, then fsyncs the directory. All I/O is
relative to pinned descriptors; records must be private, single-link regular
files on that device. An ambiguous error poisons the handle. Reopen and inspect
the actual canonical state before any retry. A valid canonical record wins over
an interrupted replacement; only that exact reserved temporary file is removed.
An initial temporary record without canonical state is neither promoted nor
deleted automatically. Corrupt canonical state preserves the temporary evidence.

The durable lifecycle is `prepared -> applying -> restored -> committed`:

- A fresh prepared ticket is published only into an empty store or over a
  committed receipt. A different pending transaction is busy; the same ID is
  replay. A new transaction must use fresh capsule entropy.
- Every decrypt/transition reloads and checks the full current record. A stale
  in-memory ticket cannot bypass a later transition/commit. Current boot must
  differ from the source boot and match device, system/app versions and target.
- Decrypt checks the complete encrypted-file digest as well as full AEAD before
  returning private plaintext. Prepared/applying allow the future applier;
  restored allows re-verification only and cannot return to applying.
- Applying can resume on another matching new boot. Marking restored requires
  that same applying boot and a caller that already durably applied/verified
  state. Commit additionally requires real runtime health supplied by the future
  integration, not a mutable marker or this state-machine API alone.
- Commit durably replaces the record with a key-free receipt before dropping the
  in-memory key. Committed records cannot decrypt. This is logical key removal,
  not a claim of forensic secure erase on an SD controller.

`Binding` is only a trusted-context carrier. It does not verify signatures, and
`BootObservation` is not independent proof of the image digests stored in the
record. Exact signed metadata/payload checks and trusted live observations must
be connected by the writer/early helper; none may be taken from p3 JSON or HTTP
parameters. Host fixtures do not exercise the production `/boot` entry point or
prove vendor FAT flock/rename/fsync and physical power-loss behavior.

## End of the restore requirement

A raw image carries `/etc/kvm/raw-restore-required`, which tells the early
helper that this rootfs is factory state until its restore commits. The
requirement ends with that commit: the helper removes the marker, so later
boots no longer read the boot ticket at all. Update attempts replace that ticket
and it lives on a FAT partition, so neither a failed attempt nor a damaged file
can keep a restored system off the network.

- A commit interrupted before the marker is removed finishes on the next boot,
  which finds its own Committed ticket. A Committed ticket of another system
  blocks instead: a fresh image never inherits an earlier receipt.
- Cleanup after the commit (capsule, marker) logs a failure and continues. The
  ticket has lost its key by then, so a leftover capsule is inert.
- The API repeats the removal for the running system before it publishes an
  outgoing ticket, after every capture refusal. This also protects systems whose
  helper predates this rule. A marker that cannot be removed stops the attempt
  before any ticket changes.
- `S01restore` treats any helper failure as blocked, including a helper that was
  killed or could not start, which cannot write the marker itself.

## Capsule sealing on the data partition (component; capture not wired)

A raw write replaces p1 and p2, so the capsule must live on p3 in a private
directory outside every media and API path. `raw_capture::seal_capsule`
encrypts a captured archive there as `<transaction>.capsule`. It writes an
exclusive 0600 temporary (a random `.capsule-*.tmp` name, `O_EXCL|O_NOFOLLOW`
relative to the pinned directory), hashes the encrypted bytes while writing,
fsyncs the file, renames it with `RENAME_NOREPLACE` and fsyncs the directory.
Any failure returns no secret and removes the temporary; a failed directory
fsync also removes the renamed capsule, which nothing could open without the
dropped secret. The SHA-256 it returns is the ticket's capsule digest, and
`RestoreSecret::transaction_id` (also in the capsule header in clear) names
the file. Host tests inject faults before the file sync, the rename and the
directory sync; vendor exFAT rename/fsync behavior and power loss are not
covered.

`raw_capture::capture` composes the capture. It takes the signed accounts from
a `TargetImage` (production: the sandbox export above), runs `capture_effective`
over the live root, seals the capsule, reopens it by name, requires the digest
the ticket will carry, decrypts it, validates the archive and checks its
accounts against the image as the early restore will, and then has the image
check the restored SSH identity. Only then does it bind a prepared ticket to
the capsule digest, both image digests from the authenticated manifest, the
source boot, the device ID, the target app version and the target. Any failure
or cancellation after sealing removes the capsule. The caller holds the update
owner and the writer drain, refuses a pending credential or Pico pair journal,
publishes the ticket and starts the writer; none of that is wired yet. Host
tests stub the image (accounts and SSH result) and run the rest for real.

`raw_capture::SandboxImage` is the production `TargetImage`. Its accounts come
from the sandbox export. Its SSH check runs three `SshPreflightJob`s against the
image: syntax, the effective policy of a fixed root connection from the
documentation address 192.0.2.10 to 192.0.2.1:22 (the default Match branch,
independent of the device's networks), and possession of every restored host
key. Every job must succeed; no particular policy value is required, because
the restored configuration is carried as it is. Each job gets its own fresh
empty private root on the root filesystem, removed after the job; a root that
does not empty keeps its unknown entries for inspection and fails the check.
`SshPreflightJob` now borrows the pinned helper, so one captured helper serves
all jobs. Host tests run the check sequence with a stub job inside a
mapped-root user namespace; the real jobs need the target.

## Raw writer core (component; writer process not implemented)

`raw_writer::write_image` copies an authenticated image snapshot onto its
partition: it refuses a partition smaller than the image before writing, copies
1 MiB chunks from offset 0, `fdatasync`s, drops the cached pages with
`POSIX_FADV_DONTNEED` so the read-back reaches the medium, reads the range back
and requires the manifest's SHA-256. The image snapshot is the immutable
anonymous spool the bundle check created, so it is not hashed again; the
read-back is the check that matters, and nothing undoes a write. Host tests
use regular files as partitions, including a change to the "medium" between
the sync and the read-back, which must fail.

The new boot partition cannot be mounted at `/boot`: that directory lives on
the root filesystem the writer has just overwritten. `Store::open_mounted`
applies the `open_boot` checks (root, block device, a single whole-device vfat
mount with the private options) at a given mountpoint; the writer will use a
directory on devtmpfs, whose mountpoint dentry stays pinned, so no path walk
reads the overwritten partition. `open_boot` is `open_mounted("/boot",
"/dev/mmcblk0p1")`.

`raw_writer::run_writer` orders the whole write over a `WriterSystem` (the
device implementation belongs to the writer process). Steps that a reboot can
still undo come first and run one at a time: stop every other process, flush
and remount the root read-only, release the old boot partition. ROOTFS is then
written and verified, then BOOT, and the prepared ticket is published on the
new boot partition last, so a failure never leaves a ticket beside a partly
written system. The outcome is `NotStarted` (nothing written; a reboot restores
the old system; also when ROOTFS cannot be opened), `Failed` (a write started:
manual recovery) or `Written`; the caller reboots after any of them. Host tests
drive the sequence with a fake system over temporary files.

`raw_writer::device::DeviceSystem` is the device implementation (not run by
host tests apart from its pure parts):

- stopping: every process in /proc except PID 1, the writer, kernel threads
  (`PF_KTHREAD`) and zombies, scanned once and tracked by pidfd; TERM, 5 s,
  KILL, 5 s; a scanned process still alive is an error (`NotStarted`).
  Processes init respawns afterwards (a console getty) are left alone.
- freezing: the new boot mountpoint `/dev/.nanokvm-raw-boot` is created on
  devtmpfs first, `sync`, then `mount -o remount,ro /` up to three times on
  EBUSY, then `sysrq u` (every filesystem read-only; the images are only read
  from here on), verified in /proc/mounts.
- releasing: `/boot` is unmounted, never left read-only, because a second
  mount of the same device would reuse the stale superblock.
- partitions: `/dev/mmcblk0p2` and `p1` opened read-write, required to be
  block devices.
- the ticket: the new p1 is mounted at the devtmpfs path with `nosuid,nodev,
  noexec,uid=0,gid=0,fmask=0177,dmask=0077`, `Store::open_mounted` publishes
  the prepared ticket, `sync`, unmount.
- logging: `/dev/kmsg` only; stderr may be a file on the overwritten root.

The writer process is the broker binary in `--raw-writer` mode. The backend
cannot run it: its native scope is a child subreaper that kills everything the
backend starts when the scope stops. The broker re-executes its own sealed
in-memory copy into this mode (`native_owner/raw_install.rs`; the engine does
not call it yet). The mode takes exactly
`--transaction`, `--version`, `--boot-size`, `--rootfs-size`, `--boot-sha256`
and `--rootfs-sha256` (lowercase hex). It returns, without touching anything,
unless it runs as root from a memfd that carries the write, shrink, grow and
seal seals; from a shell it exits 65. Otherwise the broker has already stopped
the system, so it always ends in a reboot. It takes the two images from the
`raw_transport` socket on stdin (peer: its own PID, the pre-exec creator) and
loads the prepared ticket from the current boot partition. It requires that
ticket's transaction and image digests to match its arguments, and closes the
store before `/boot` is released. It sends stdout and stderr to `/dev/null`
(the broker's are a log file), runs `run_writer` with the device system, logs
the outcome to the kernel log, syncs and reboots (`reboot(2)`, then sysrq `b`).

`sealed_copy` copies a program into a memfd and adds the write, shrink, grow
and seal seals once the copied length matches the source. `exec_writer` builds
the fixed writer arguments and marks every descriptor above stderr
close-on-exec, so the leases, the journal and every other broker descriptor
close at the exec boundary. It then makes the images' transport socket stdin
and calls `fexecve` with an empty environment. It returns only if the exec
failed, and the broker then stays fail-closed. A host test runs the real broker
binary this way as root in fresh user, mount and PID namespaces, with the
kernel log bound to a file. The writer receives both images over stdin and
stops at the missing ticket store; images sent under another context are
refused before the ticket. There the writer's reboot ends only the namespace.

The backend hands the raw write to the broker as one sequenced packet
(`update/raw_install_lease.rs`, `NKRAWL01`): the prepared ticket's transaction,
both image sizes and SHA-256 digests, and the device/inode identities of five
descriptors, namely the update, writer-admission and writer-activity exclusions
(as for an app install) and the two image snapshots. Only a system-install
operation can prepare it, and sending it never reports more than "queued". The
receiver checks each exclusion as for the app handoff: the exact protected
directory, read-only, close-on-exec and exclusively locked by the same open
description. It checks each image as the writer's transport does: an anonymous
regular file of the expected owner, writable by no one else, opened read-only
and close-on-exec, of exactly the declared size and identity. The broker keeps the exclusions until the exec boundary, where
close-on-exec releases them. The client side connects only to the fixed
root-only `raw-install.sock` in the broker's journal directory. The broker does
not bind that endpoint yet; accepting an offer, re-reading the ticket, stopping
the scopes and the exec are the next step.

## Required writer/boot integration (not implemented yet)

App/system front-end work now shares a runtime job owner and cooperative
cross-process admission lease. Account/Config/firewall writers also have partial
admission/drain enrollment; the composed firewall rollback stop/join boundary is
host-tested, but no production capture consumes it yet.
Exact lifetime guarantees and remaining raw-child/quiescence/durable-transaction
gaps are documented in [security-update-ownership.md](security-update-ownership.md).
This does not satisfy the complete protected writer requirements below.

1. Hold the common update transaction lock. Retain exact metadata/signature;
   reverify current trust policy and archive identity. Do not authorize from
   `staged.json`, old raw markers or copied preservation trees.
2. Stop configuration writers. Before enabling capture, maintain a finite
   producer inventory with each persistent source's owner, enrollment or explicit
   stop+join, and completion/abort boundary. Backend exit alone is not proof that
   helper/daemon/background writers stopped. A pending credential journal
   (`/etc/kvm/pwd.journal`) refuses capture: until the next start restores it,
   `/etc/shadow` and `/etc/kvm/pwd` may hold different passwords. Capture the
   current allowlisted
   account, SSH, network and application state from live trusted rootfs/bootfs. Any critical
   read/copy/space error aborts before partition writes. Preserve optional app
   configuration/state, never downloaded binaries, caches or init scripts.
   Use the implemented canonical app-state capture/checks with the exact active
   config/cwd and exact signed-image native account tables. Use the implemented
   collision-free native merge and unknown-field
   reject/migration preflight; do not claim arbitrary YAML is losslessly copied
   or bypass the error by normalizing the source file in place.
   Use the implemented immutable SSH snapshot/path guard without rescanning its
   completed tree or rereading its pinned enablement flags. Validate full SSH
   host identity/config/effective policy and signed-image shell/home
   executable/ownership requirements before writing; native row checks alone
   are not proof of a working SSH service. Require the implemented private-key
   possession probe within the verified target runtime as well as signed sshd
   config/effective-policy/certificate checks; `-y`/`sshd -t` alone are not a
   mathematical private-key proof.
   Installed optional apps need a verified
   replacement/provenance check before flashing; silently dropping them is not
   acceptable preservation. Regenerate shell-sourced defaults and runtime links
   from authoritative time/syslog/network settings using signed-image code.
3. Build and validate a bounded regular-file archive in private rootfs staging.
   Reject traversal, duplicate paths, links, special files, sparse/extension
   entries, unauthorized paths/modes and expansion/count/size violations before
   any restore application. Preserve users' script uploads as inert data under
   an explicitly gated administrative path, not auto-starting privileged code.
4. Seal to a private unpublished capsule; sync all bytes and the containing
   directory. Publish its one-time protected ticket only after successful sealing.
   Retain ticket/key/runtime helpers outside overwritten partitions while flashing.
5. Write verified immutable raw images. The signed raw rootfs must already carry
   an explicit restore-required discriminator, distinct from factory/full-SD
   provisioning, before the first partition write. Its absence cannot be inferred
   from mutable p3 markers. A raw image missing its protected ticket must fail
   closed, not look like a fresh installation. The current packaging has no such
   discriminator; distinct raw/factory rootfs variants and hashes must be handled
   explicitly rather than patched after writing. Drop old bootfs descriptors
   before unmount/overwrite; retain the ticket privately across that boundary.
   Reopen new p1, republish prepared state with the tested FAT mount masks and
   sync. On any ambiguous I/O failure, inspect durable state
   before retry; never pretend whole-device power-loss rollback is automatic.
6. Run a minimal signed-image helper before network/SSH/backend/provisioning.
   Verify target version, authorized transaction, source/new boot identity and
   ticket state; authenticate the whole capsule and validate the archive into a
   private staging area. Preflight free space and required identity files.
   Failure must stop the whole management/provisioning boot path: merely returning
   nonzero from S01fs is not sufficient if rcS continues to later init scripts.
   Keep the retired legacy preserve/marker restore path disabled, including its
   permission fixups. The old S01fs `server.yaml` mode `0644` behavior is removed, not a
   substitute for implementing this helper. No later boot script may overwrite
   authenticated state or weaken its required mode `0600` permissions.
7. Apply only from the already-verified open descriptor/private snapshot. Durable
   state is `prepared -> applying -> restored -> committed`. Restarts continue
   the same authorized transaction idempotently. Pending/invalid restore cannot
   start management/provisioning with incomplete or default identity.
8. After durable commit, retain only the key-free protected receipt and remove
   exact managed capsule paths. Do not broadly delete legacy preserve/cache or
   other users' recovery data.

Rootfs executables, init scripts, update keys and policy come from the signed
image. Optional apps need verified provenance/reinstall. `/etc/resolv.conf` and
other runtime symlinks are regenerated from preserved authoritative settings,
not restored as arbitrary archive links. Old `usb.disk0` content is not a backing
path; restoring disk enablement can only enable an empty file-backed drive.

## Acceptance still required

Core fixtures cover header/body/tag mutation, chunk reorder/duplicate/drop,
truncation/trailing data, wrong key/context, size limits, read/write/flush errors,
private spool ownership and actual process-kill cleanup. Archive fixtures cover
synthetic capture -> seal -> authenticate -> validate -> indexed read, explicit
absence, sensitive configuration preservation, canonical modes, malformed tar
and resource limits, static aliases and concurrent parent-directory swaps.
Ticket fixtures cover the fixed record, every-byte corruption, invalid inner
fields, lifecycle/replay/stale handles, wrong boot/device/version/target before
ciphertext reads, exact encrypted digest, privacy/aliases/locks and pinned-parent
renames. I/O faults at six publication boundaries poison the handle and reopening
observes actual old/new canonical state. Actual child-process kills before/after
rename also prove host lock release and recovery; they are not power-cut tests.
The real early helper/applier, remaining config/native semantics, production
ticket integration, native SSH/service-account validation, raw writer integration,
p1 overwrite, physical crash/reboot boundaries, ENOSPC/sync failures and full
device preservation are separate remaining gates. No capsule test is
device/raw-update acceptance.
