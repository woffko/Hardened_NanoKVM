# PicoClaw credential-file pair publication

Rust reads and publishes `config.json` and `.security.yml` through checked
descriptor-relative rootfs I/O and a private pair journal. This gives enrolled
Rust operations a recoverable, coherent pair; it is not the complete PicoClaw
privilege/service boundary or a claim about independent native readers.

## Supported storage and compatibility

The selected `PICOCLAW_HOME` remains supported, including UTF-8 directory names,
spaces and a relative home interpreted from the server's cwd. Every existing
ancestor must be root-owned on the root filesystem, without group/world write
or special permission bits. Symlinks, magic links, parent traversal and crossing
mounts are rejected. A custom home on another mounted filesystem, including
public USB storage, is not supported by this private-rootfs protocol. It fails
before writes; it is not silently redirected to the default home.

Rust, the fixed native role command and the new bundled S96 use the same lexical
home selector. `nanokvm-native-ctl picoclaw-home` is a read-only path query: it
does not connect to the broker, create directories, onboard or repair state.
Unset/Unicode-whitespace-only values select `/root/.picoclaw`; relative values
become absolute before S96 changes cwd. Spaces and UTF-8 names are retained;
parent traversal, control characters, non-UTF-8 or overlong effective paths fail
explicitly, without fallback. `HOME`/passwd do not select a second default.
Existing non-root/passwd-selected layouts need an explicit compatible
`PICOCLAW_HOME`, not discovery or reset. Missing/old ctl support refuses setup.
This is not a persistent broker home/generation binding: independent launchers
with different overrides/cwds can still select different homes. Absolute,
consistent service configuration and the retained migration remain required.

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

Rust model/default updates serialize and size-check both JSON and YAML before
changing either destination. Writes require a Config permit and exclusive
nonblocking flock on the checked home directory. Rust readers use a shared
directory lock and recheck both names around their bounded reads. A competing
writer returns a busy error rather than exposing its intermediate pair.

The destination and its parents are checked before publication. A random
exclusive temporary file in the pinned directory is 0600 before plaintext is
written. Its complete contents are synced,
the destination revision is rechecked, then an atomic rename publishes the file
and a directory sync fences success. First creation uses no-replace rename.
Existing open readers keep the old inode instead of observing in-place truncation.
Serialization/read buffers use zeroizing owners; this is not a claim that every
parsed string or native-runtime copy is erased from memory.

The private `.picoclaw-config-pair` journal contains the complete desired pair,
presence flags and old content hashes. A versioned, length-bounded header and
SHA-256 checksums reject corruption, unknown schemas, truncation and trailing
bytes. Its maximum size is two 4 MiB documents plus a 192-byte header. It has
the same root-owned, 0600, single-link/no-symlink/no-mount requirements. The
checksums detect corruption; they are not authentication against a root writer.

After syncing the journal file, no-replace rename and parent sync commit its
intent. Each canonical file is then published and parent-synced. Recovery first
requires BOTH canonical members to match their recorded old or desired content;
foreign contents or unsafe metadata stop recovery without repair. Existing
same-byte regular private inodes may be accepted: this is not arbitrary-root
writer compare-and-swap. The complete canonical pair is rechecked before exact
journal inode/revision validation, unlink and final parent sync.

A reader seeing a valid pending journal returns its complete desired pair,
after validating the canonical old/new states, without performing writes.
Config-owned onboard preflight and subsequent pair writes roll that intent
forward. Recovery first syncs the checked journal fd and directory again: a
visible journal rename from a crashed process is not proof of its durability.
A corrupt journal never falls back to the canonical files. No automatic
rollback or blind retry is promised after an ambiguous I/O error.

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

The two canonical names still change separately. Independent native readers
that ignore the directory lock/journal can observe an intermediate pair.
Native stop/join/enrollment and start-after-recovery integration therefore remain
mandatory. Raw capture must settle or reject a pending journal under the effective
home/service barrier before reading canonical files. The journal is not silently
added to the preserved archive schema, nor is a Rust Config permit proof that
native writers are stopped. All writers must be enrolled or stopped/joined.

Profile/workspace/session/installer and independent service/local-tool writers,
broker-frozen effective-home alignment and non-root service-user migration, stale-temporary recovery,
fault-injected kernel I/O/fsync outcomes, native onboard acceptance, device tests
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

Pair fixtures additionally kill and reap the real writer at ten publication
boundaries across existing-pair, empty-home and absent-YAML states. They check
read-only coherent journal views, busy readers during mixed canonical state,
idempotent roll-forward, exact journal retirement, corrupt/unsafe/foreign-state
refusal and preservation/non-adoption of private orphan temporaries. These are
SIGKILL tests, not physical power-cut or kernel-fault-injection evidence.
