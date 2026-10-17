# Authenticated raw restore transaction

Status: implementation in progress on the security remediation branch. Only
the capsule core below is implemented/tested so far. Existing raw writer and
early boot still use legacy preservation and must not be released as fixed C1.

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
It writes into an owner-only rootfs file unlinked and directory-synced **before**
the first plaintext write. Only after full authentication/fsync/rewind does it
return a read-only `Read + Seek` descriptor wrapper. It exposes no filename or
write API. Errors and process termination cannot leave a named partial plaintext
spool. A failed output/flush does not return a usable restore secret.

Replay protection is deliberately not claimed by encryption: it belongs to the
durable protected ticket state machine below. AEAD also does not validate an
archive's filenames, entry types, modes or account semantics.

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
private spool ownership and actual process-kill cleanup. The real early helper,
archive allowlist, persistent tickets/replay, raw writer capture, p1 overwrite,
crash/reboot boundaries, ENOSPC/sync failures and full device preservation are
separate remaining gates. No capsule test is device/raw-update acceptance.
