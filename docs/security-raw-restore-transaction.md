# Authenticated raw restore transaction

Status: implementation in progress on the security remediation branch. Capsule
crypto, closed-schema archive capture/validation and descriptor-relative source
I/O are implemented and host-tested. Existing raw writer and early boot still
use legacy preservation and must not be released as fixed C1.

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
identity files must be present and nonempty. Presence of `session_secret` or
`server.yaml` is a structural minimum, **not** semantic validation of effective
authentication configuration.

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

References checked for the implementation:

- [RustCrypto ChaCha20Poly1305 0.10.1](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/)
- [RustCrypto STREAM implementation at aead-v0.5.2](https://github.com/RustCrypto/traits/blob/aead-v0.5.2/aead/src/stream.rs)

## Required writer/boot integration (not implemented yet)

1. Hold the common update transaction lock. Retain exact metadata/signature;
   reverify current trust policy and archive identity. Do not authorize from
   `staged.json`, old raw markers or copied preservation trees.
2. Stop configuration writers. Capture the current allowlisted account, SSH,
   network and application state from live trusted rootfs/bootfs. Any critical
   read/copy/space error aborts before partition writes. Preserve optional app
   configuration/state, never downloaded binaries, caches or init scripts.
   Resolve custom account/session/TLS paths into protected canonical state and
   validate effective configuration. Installed optional apps need a verified
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
5. Write verified immutable raw images. Restore ticket to new p1 with the tested
   FAT mount masks and sync. On any ambiguous I/O failure, inspect durable state
   before retry; never pretend whole-device power-loss rollback is automatic.
6. Run a minimal signed-image helper before network/SSH/backend/provisioning.
   Verify target version, authorized transaction, source/new boot identity and
   ticket state; authenticate the whole capsule and validate the archive into a
   private staging area. Preflight free space and required identity files.
7. Apply only from the already-verified open descriptor/private snapshot. Durable
   state is `prepared -> applying -> restored -> committed`. Restarts continue
   the same authorized transaction idempotently. Pending/invalid restore cannot
   start management/provisioning with incomplete or default identity.
8. After durable commit, remove the one-time key/ticket and exact managed capsule
   paths. Retain a non-secret receipt that rejects replay. Do not broadly delete
   legacy preserve/cache or other users' recovery data.

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
The real early helper/applier, semantic auth validation, persistent tickets/
replay, raw writer integration, p1 overwrite,
crash/reboot boundaries, ENOSPC/sync failures and full device preservation are
separate remaining gates. No capsule test is device/raw-update acceptance.
