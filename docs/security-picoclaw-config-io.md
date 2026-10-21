# PicoClaw credential-file publication

Rust reads and publishes `config.json` and `.security.yml` through checked
descriptor-relative rootfs I/O. This is a per-file boundary, not a two-file
transaction or the complete PicoClaw privilege/service boundary.

## Supported storage and compatibility

The selected `PICOCLAW_HOME` remains supported, including UTF-8 directory names,
spaces and a relative home interpreted from the server's cwd. Every existing
ancestor must be root-owned on the root filesystem, without group/world write
or special permission bits. Symlinks, magic links, parent traversal and crossing
mounts are rejected. A custom home on another mounted filesystem, including
public USB storage, is not supported by this private-rootfs protocol. It fails
before writes; it is not silently redirected to the default home.

Existing credential files must be root-owned regular single-link files with
mode 0600. Reads are bounded to 4 MiB per file and compare inode/metadata revision,
including modification/change times, before and after reading. Malformed
documents remain parse errors; valid YAML scalar/null compatibility is unchanged.
Missing `config.json` is an error for reads;
missing `.security.yml` remains an empty mapping for compatibility. Invalid
contents/metadata are not automatically repaired, deleted or replaced.

The limit applies to serialized file bytes; oversize updates fail rather than
truncate a document. Other model/provider/custom fields remain intact. Existing
unsafe paths/permissions need explicit administrative migration, not automatic
adoption of potentially exposed credentials.

## Publication and writer ownership

Rust JSON/YAML writes require a Config permit. The destination and its parents
are checked before publication. A random exclusive temporary file in the pinned
directory is 0600 before plaintext is written. Its complete contents are synced,
the destination revision is rechecked, then an atomic rename publishes the file
and a directory sync fences success. First creation uses no-replace rename.
Existing open readers keep the old inode instead of observing in-place truncation.
Serialization/read buffers use zeroizing owners; this is not a claim that every
parsed string or native-runtime copy is erased from memory.

Temporary cleanup checks inode identity before unlinking its own name. Cleanup
on failure is best-effort, not a durable orphan journal/GC protocol. A power loss
can leave a private temporary. If the rename succeeds but the directory sync
fails, the result is indeterminate durability: an error does not mean no bytes
were changed. There is no automatic rollback or blind retry guarantee.

Rust-initiated first-run `onboard` is enrolled in the same Config domain. Under
the permit it rechecks whether setup is needed, creates/checks missing private
rootfs ancestors, waits for the script and validates the resulting documents
before releasing ownership. The owned callback survives HTTP receiver loss.
The bundled S96 script uses umask 077 for new files/directories. Its independently
invoked lifecycle, an older installed script and the external binary's own
publication/forking semantics are not made safe merely by this enrollment.

## Remaining transaction/lifecycle work

JSON and YAML are still published separately. Model/default updates need a
durable pair journal/recovery and coherent readers; a Config permit alone does
not provide crash atomicity or prevent an unenrolled producer. Replacement of
an existing destination is not a kernel compare-and-swap against arbitrary root
writers. All writers must be enrolled or stopped/joined before raw capture.

Profile/workspace/session/installer and independent service/local-tool writers,
effective-home alignment with non-root service users, stale-temporary recovery,
fault-injected rename/fsync outcomes, native onboard acceptance, device tests
and raw migration remain open. PicoClaw local tools still need H2 isolation.
Target GUI/HID/BIOS/terminal autonomy is unchanged by this file protocol.

## Host verification

```sh
cargo test --manifest-path server-rust/Cargo.toml --locked --offline --lib \
  --features sandbox-test-fixture picoclaw -- --include-ignored --nocapture
```

The actual Rust load/save helpers run in disposable user/mount namespaces with
a private chroot and synthetic data. Cases cover destination symlink/hardlink,
inode replacement, first creation, missing YAML, malformed documents, unsafe
modes/directories/FIFOs/ancestors, oversize refusal, private-home setup, relative
cwd and a real private tmpfs mount boundary. This does not exercise an installed
PicoClaw binary, authenticated router, actual device or physical power loss.
