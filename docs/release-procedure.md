# Release Procedure

A combined release (app update, raw system update and full SD image) is made in
two separate steps: `scripts/prepare-release.sh` builds a local release
directory from the accepted candidate files, and `scripts/publish-release.sh`
publishes it. Publication needs its own explicit approval. The RC11 and RC12
helpers refuse to run unless `HARDENED_LEGACY_RC11=1` or
`HARDENED_LEGACY_RC12=1` asks for them.

## Building the candidate

`scripts/build-kernel-5.10.265-candidate-run.sh` runs the whole system
pipeline (kernel, modules, runtime, rootfs, `boot.itb`, recovery SD) for a
candidate, in the style of the RC12 wrapper. It pins what the remediation
fixed: the accepted RC12 kernel fragment by hash, kernel release
`5.10.265-tag-`, the production update key, and the refreshed Buildroot
security source (OpenSSL 3.6.5, OpenSSH 10.6p1, expat 2.9.0, curl 8.23.0,
wpa_supplicant 2.12). It takes from the environment, and refuses to start
without, what the owner decides: `EXPECTED_SYSTEM_VERSION` and
`EXPECTED_KVMAPP_VERSION` (an already published version is refused),
`EXPECTED_KVMAPP_SERVER_SHA256` of the accepted application stage,
`NANOKVM_KVMAPP_SOURCE_DIR` (the stage; its version file must match) and a
new `KERNEL_5_10_265_REPRO_ROOT`. Run it twice with independent run roots
for the G5 comparison. The underlying `build-kernel-5.10.265-repro-run.sh`
also refuses a dirty worktree and an existing run root. The wrapper signs
and publishes nothing.

`scripts/build-kernel-5.10.272-candidate-run.sh` is the 5.10.272 variant. It
pins the clean merged source tree
`build/latestbuildroot/kernel-5.10.272-v1/repo`, the merge commit
`ddef97c3d978b67f7852dca05f0b3505f798c0b2`, its signed stable parent
`aca95a35f1bcc0626c4fa4d1252bf2d4c990a1a2`, kernel release `5.10.272-tag-`,
the same accepted RC12 fragment hash, refreshed r2 source and production key.
It takes the same owner inputs but requires a new
`KERNEL_5_10_272_REPRO_ROOT`; run it twice with independent roots for G5. The
5.10.265 wrapper remains for reproducing the RC12 baseline.

## Preparing

The inputs are the files that passed candidate acceptance, each with its
SHA-256 pinned in the environment: `APP_INPUT_SHA256`, `SYSTEM_INPUT_SHA256`
(the raw system archive) and `SD_INPUT_SHA256`. The ROOTFS and BOOT images
inside the raw archive are pinned too (`ROOTFS_SHA256`, `ROOTFS_SIZE`,
`BOOT_SHA256`, `BOOT_SIZE`), with the operation the bundle must declare
(`RAW_REQUIRED_OPERATION`). The comment at the top of the script lists every
variable. Nothing is signed until:

- the worktree is clean, and the build commit is an ancestor of `HEAD`;
- every input is nonempty and matches its pin;
- the raw bundle passes `scripts/verify-raw-bundle.sh`: signed metadata, the
  expected key ID, versions, kernel, source commit and operation, and the
  pinned image hashes and sizes;
- the app archive holds the expected version.

The release is assembled in a staging directory next to `OUTPUT_DIR`. The app
metadata is signed and must verify with `PUBLIC_KEY`. The SD image is
compressed and checked by decompressing it again. `SHA256SUMS` lists every
asset, and `RELEASE_MANIFEST.json` (`scripts/release-manifest.py`) records each
asset's size and SHA-256, the notes, the release fields (tag, versions, key ID,
source and build commits) and the input pins. The directory is renamed into
place only after the manifest check passes, so a failed run leaves no release
directory. `--draft` marks it `DRAFT_ONLY`, which publication refuses.

## Publishing

`PUBLISH_RELEASE=1 RELEASE_DIR=... RELEASE_TITLE=... scripts/publish-release.sh`
first checks, before any remote write:

- the directory holds exactly the manifest's files, each unchanged;
- `HEAD` is the commit the release was prepared from, and the tree is clean;
- the notes name no release blocker;
- both metadata signatures verify.

It then runs these steps, writing each to the receipt
`<RELEASE_DIR>.publish/receipt` before and after it runs:

1. `backup`: download the current app and system channel metadata and
   signatures into `<RELEASE_DIR>.publish/backup/`. An earlier backup is
   never replaced.
2. `draft`: create the release as a draft with the manifest's assets.
3. Download the draft again; it must hold exactly those assets, byte for byte.
4. `publish`: publish it without marking it latest.
5. `app-channel`, then `system-channel`: replace the four metadata files of
   `hardened-rust-preview` and `hardened-system-preview`. Download them again
   and verify each signature.
6. `latest`: mark the release latest and compare the latest download URL.

A rerun reads the receipt (bound to the tag and the manifest hash) and skips
the steps that are done. A step that began but has no recorded end is checked
against the remote state first and repeated only if it did not happen. So a
lost reply is never answered with a second write, and a partial or changed
draft stops the run before any channel changes. Versioned release assets are
never replaced. The channel metadata is the only thing overwritten, and its
previous files stay in the backup. If a channel step fails, the error names
the backup. A rerun finishes the step, or `gh release upload <channel>
--clobber` with the backup files restores the previous state.

GitHub does not replace several assets atomically. During a channel switch a
device can fetch a metadata file and a signature of different generations; it
then refuses the update on the signature and tries again later.

## Tests

`scripts/test-release-pipeline.sh` runs both scripts in a scratch copy of the
repository, with a throwaway key, synthetic candidate files and
`scripts/fixtures/fake-gh.py` in place of `gh` and `curl`. No network or real
key is used. It covers a tampered app archive, SD image or system archive, a
system archive its metadata does not sign, a missing signature, a signing key
that is not the release key, raw images other than the accepted ones, an empty
input, notes with a blocker and a dirty worktree. Each is refused before
anything is signed. It also covers an extra, missing or changed asset, a
draft-only release and a release prepared from another commit: each is refused
before any remote write. Then come the full publication order, a rerun after
completion, a partial draft, an asset that changes on upload, a lost reply and
a failed channel switch. `scripts/test-legacy-release-helpers.sh` checks the
legacy guards.
