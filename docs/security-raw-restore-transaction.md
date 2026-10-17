# Authenticated raw restore transaction

Status: implementation in progress on the security remediation branch. Capsule
crypto, closed-schema archive capture/validation, canonical app/native-identity
checks, SSH configuration-path guards/snapshots, protected ticket persistence and
descriptor-relative source I/O are implemented and host-tested. Existing raw
writer and early boot still use legacy preservation and must not be released as
fixed C1.

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

**The legacy raw writer does not yet consume these descriptors.** It still
reopens extracted payload paths; verification here cannot authorize later reads
from that mutable tree. An isolated descriptor-bound writer and signed runtime
binding remain required before C1 closure. File-update bundles use the direct
bounded manifest but retain their legacy remaining payload/framing validator;
the closed raw framing claims above do not apply to the non-raw early return.

**C1 remains open.** The snapshot closes later source-inode mutation but is not
protection from malicious local root or raw writes to its backing filesystem.
Extraction destinations, some legacy record reads, extracted raw payloads and
the raw/early writer are not yet an immutable descriptor-owned transaction.
USB p3 exclusion, isolated writer,
signed-target runtime/rootfs binding, protected tickets, early fail-closed apply,
private app staging and device/crash/release gates remain mandatory. Do not ship
this partial system-API improvement as the completed security migration.

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
There is no signed-image root builder or production caller yet. A pathname,
private mode, ELF header or successful syntax exit never grants restore authority.

The root is owner-0 and private, with no setid/sticky bits; the bounded tree
rejects symlinks, special files, hard-linked regular files, writable group/world
modes and nested mounts. Limits are 1024 members, 64 MiB, depth 16, path 240 bytes.
`.oldroot`, `proc`, `sys` and `data` must be empty. `/dev/null` starts as an empty
regular placeholder. Fixed `usr/sbin/sshd` must be a regular executable. Signed
library symlinks must eventually be resolved/materialized as checked regular
files, not copied as ambient path authority. Hostile concurrent local root is
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
connection/session or `Authorized*Command` sandbox. No `-T` output/policy parser,
certificate/Match matrix or root-password availability proof is implemented.

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
The previous possession-probe API uses a parent proc-fd view; it cannot be run
unchanged in this no-proc sandbox. Its required isolated input transport/native
command mode must be integrated without reintroducing host proc or outside fds.

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
context. Device identity must come from stable hardware, not a cloned machine-id.

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

## Required writer/boot integration (not implemented yet)

1. Hold the common update transaction lock. Retain exact metadata/signature;
   reverify current trust policy and archive identity. Do not authorize from
   `staged.json`, old raw markers or copied preservation trees.
2. Stop configuration writers. Capture the current allowlisted account, SSH,
   network and application state from live trusted rootfs/bootfs. Any critical
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
   Disable the complete legacy preserve/marker restore path, including its
   permission fixups: old S01fs can chmod server.yaml 0644. No later boot script
   may overwrite authenticated state or weaken its required 0600 permissions.
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
