# Update Key Transition 2026 Q3

Status date: 2026-08-28.

Status: the production trust set, independently restorable encrypted backups,
the corrected reproducible bridge app, exact published app `2.0.40`/raw.10,
app `2.0.41`/raw.11 and app `2.0.40`/raw.12 compatibility paths are accepted.
The rebuilt RC12 matrix passes A/B reproducibility, production signing and live
signed-raw acceptance plus the new full-SD initial, expansion, runtime and
two-reboot gate. Its physical raw.10 recovery and final RC12 return also pass.
All gates pass. The manual transition prerelease
`hardened-rust-2.0.42-key-transition` and combined latest release
`hardened-system-0.3.0-raw.12` were published from commit `8be6b4d` on
2026-08-28. Independent downloads prove exact assets, both production-signed
Preview metadata channels and the GitHub latest metadata redirect. The retained
remote acceptance report SHA-256 is
`d70e156c865c28c340d39c9ec085cfc73d66b20360bce533db8ef6644ca43c9d`.

## Trust Set

- production key ID: `hardened-system-prod-2026q3`;
- algorithm: RSA-4096 with SHA-256 PKCS#1 v1.5 metadata signatures;
- production public-key DER SHA-256:
  `97ddb5600accf0e431c74f82b03acf249668bf75fe0de2e41724c91720516f75`;
- historical IDs retained during the bridge window:
  `hardened-system-dev` and `hardened-system-test`. The window closed with
  application `2.1.3`: its policy lists the production key ID alone, and a
  device that runs it refuses metadata signed with a historical ID.

The production private key is stored outside the repository. It must never be
placed in Git, Project Memory, build archives, command arguments, logs or
device images.

Two independently salted AES-256 PKCS#8 backups were created on the WSL and
Windows filesystems. Both restore in-memory to the production fingerprint. The
encrypted ciphertext SHA-256 values are
`889f5ca50f56b75231cf12821c62bcbcd5a5b39a325d60a7ff2c6b8e1c53c561`
and `eaeba2ae41bdeb036670015c342fe0455e86fbcdb2f83ba8779f2656b6f22135`.
Both encrypted copies were independently restored and fingerprint-checked. One
encrypted copy was additionally moved off-host, and the user-reported
destination ciphertext SHA-256 matched
`eaeba2ae41bdeb036670015c342fe0455e86fbcdb2f83ba8779f2656b6f22135`.
The storage location is intentionally not recorded.

## Corrected Reproducible Bridge Artifact

The first bridge archive was superseded after the app `2.0.40` compatibility
test exposed a lifecycle defect: the first restart could still be executing an
old in-memory `S95nanokvm` shell script after it copied the new script over
itself. Runtime production trust then appeared only after a second restart or
OS reboot. Commit `4d46c8b` makes the new Rust server idempotently install the
bundled trust set before serving HTTP on its first start. `S95nanokvm` retains
the same idempotent operation for later service starts and boots.

Commit `ac12e2d` also removes build-host paths from `MANIFEST.txt`. Two fully
independent Cargo targets now produce the exact same RISC-V server, manifest
and 22,495,269-byte archive:

`build/key-transition-2.0.42-bootstrap/app-a/out/hardened-nanokvm-kvmapp-2.0.42.tar.gz`

SHA-256:
`aa0cd78c1b2e9951f216826c44b4b7ff2fb211fc1980540366f8f5b1f7e0dd20`.

The RISC-V server SHA-256 is
`fd116fc459a1961cfc16fd0c7077a8f4c5e24d8f32d8745fd3b9744217083d6d`.
The archive embeds app `2.0.42`, the unchanged legacy public fingerprint
`2167216b8ccca472124a0f5bfc7889a3ab55772c221d8540e577243a1aa90926`,
production fingerprint
`97ddb5600accf0e431c74f82b03acf249668bf75fe0de2e41724c91720516f75`,
the three-ID bridge policy and no private-key entry. The reproducibility report
SHA-256 is
`065c636e8c9e05c9fcbbe13313b6ee3d728c605e7fc252b6ffa69215ea5381c2`.
The old `e9c0bb08...` archive and its device evidence are superseded.

Host acceptance includes 8 focused trust tests, all 165 Rust tests, a
baseline-aware Clippy pass and the Buildroot security-policy test. The tests
cover malformed/unknown key IDs, policy exclusion of retained legacy files,
source and destination symlink handling, atomic replacement, permissions and
idempotence.

## Accepted App 2.0.40 Compatibility Path

Test device `10.0.87.49` was returned to app `2.0.40` with legacy trust only,
then updated through the authenticated HTTP offline-upload API. The corrected
server installed the production key and policy during its first start, before
any second restart or reboot. The test preserved the account, raw.12 system,
Linux `5.10.265-tag-`, SSH identity and both runtime processes. Production and
historical signatures passed, a full reboot changed the boot ID and preserved
the complete state, and the post-reboot browser login succeeded.

| Evidence | SHA-256 |
| --- | --- |
| downgrade upload | `4d35fd574299c79b0d408c19f85cc43b9467476c0b96710c16ab2ca7ebf44608` |
| clean app `2.0.40` preflight | `7121d726ac76d30cfd906e4e3f9e24730193d788a8f52ec57288e86c51839628` |
| corrected bridge upload/restart | `a11abc0603cbadf8ed5facece26117733ecfbb09bf3eb80f9f77ff76b8f7e406` |
| immediate trust/runtime postflight | `06efaaf05a71d80314072c82be059713dae625468a12908ed22abf18ad7cbd2a` |
| signature matrix | `f6482d1f6684d878cf0a4b22d2c5ad6942864b9b64d815c2db00d83a2eefb320` |
| post-reboot trust/runtime | `c401615157e95bd682b8146903fa49021bb80e7bb18c85bf91f64b429f634eff` |
| post-reboot web login | `e197729926ca48d45241c8fa387c0e9a1adfbb8afd88cad5b9b3827dc478db55` |

This proves the application transition from `2.0.40`, but the system on this
device was raw.12. It is not presented as proof of the exact raw.10 gate.

## Accepted App 2.0.41 / Raw.11 Bridge

Test device `10.0.87.133` was restored to app `2.0.41`, system
`0.3.0-raw.11`, kernel `5.10.4-tag-`, legacy trust only and no policy. The
authenticated HTTPS offline API accepted the corrected bridge. Immediate
postflight, the production/legacy signature matrix, a full reboot and the
post-reboot browser login all passed while preserving the account, SSH host
identity, system and both runtime processes with zero kernel alerts.

| Evidence | SHA-256 |
| --- | --- |
| downgrade upload | `3f899329163eb8643c7279cc31027b44f4f2499d9b548697ab0bcebabfb98932` |
| clean app `2.0.41`/raw.11 preflight | `aae1b89613048152b0b090a7d02937eb7bc0a601a4e6c132a0195f83fbd8569f` |
| corrected bridge upload/restart | `8d847f1e82c974e59db72fb4a8c21e9f82a74dc9af7b483e8656698010535920` |
| immediate trust/runtime postflight | `c1117411c35e506db0d8c8522c4db0bad34adbf9b8d904933022a1df432dffc4` |
| signature matrix | `f6482d1f6684d878cf0a4b22d2c5ad6942864b9b64d815c2db00d83a2eefb320` |
| post-reboot trust/runtime | `46124270aaf4deaa5823127e908066bf2ef4cfaaa0bb52847601b2aea1930732` |
| post-reboot web login | `19d415429dafff04eecd57555997fb78ff10bc21904d13f4a80768cc5aa1fc4e` |

## Accepted Exact Published App 2.0.40 / Raw.10 Gate

The normal system downloader correctly rejects downgrades and must not be
bypassed. The published full RC11 image was therefore downloaded for a
physical recovery-card test:

`build/key-transition-2.0.42-bootstrap/raw10-gate/Hardened_NanoKVM_2.0.40_RC11_System_0.3.0-raw.10_Buildroot-2026.05.1.img.xz`

Its GitHub digest and downloaded checksum both match
`96e44ee8eb482ba2609348164b8c80ac1b94a1c1152db328331fba799d5e0632`,
and `xz -t` passes. The image booted on recoverable hardware with the exact app
`2.0.40`, raw.10 and kernel `5.10.4-tag-` source state. The corrected bridge
installed through authenticated Offline Update, established the exact dual
trust and policy on its first start, passed historical and production
signature checks, preserved the account, MAC, SSH identity, system and runtime,
and passed a real reboot plus authenticated browser login as app `2.0.42`.
Evidence hashes and the retained procedure are in
[`rc12-final-physical-gates.md`](rc12-final-physical-gates.md).

## Accepted RC12 Production-Key Chain

Two clean full pipelines from build commit `9567b5f` are exact through kernel,
57 modules, runtime staging, Buildroot rootfs, FIT, full image, compressed image
and extracted payloads. The retained A/B report SHA-256 is
`d201611d70a4922cc08a1d456bd14c2c2307d35104a6ae90ac42f00283d758c2`.
Selected rootfs SHA-256 is
`b840bd08f2c708b45b527d005719b6d5dc6a7b1ba66922b8e161b570a950c760`;
selected compressed-image SHA-256 is
`a6069020dd92c024793cbb84500887a766f07263f8a6241b9462e6e0ca95dae0`.

The installable raw.12 archive is signed by
`hardened-system-prod-2026q3`, requires app `2.0.42`, and passes the exact
payload/signature verifier. Archive SHA-256 is
`cf6bbef5599197f4b5ed926f22bed12352f2fdc275eb8f32fc8344d3ed7eae96`;
verification-report SHA-256 is
`d6627d560c68f57425ef6ad60b3adc47231c82bd6918330c1897e9ac0bf795b7`.

On `.133`, the stock updater accepted this exact signed bundle from the
accepted bridge/raw.11 state, restored configuration, confirmed boot-good,
cleared the pending marker and disabled raw mode. Exact runtime, an additional
reboot, browser login, the complete 13-step software regression suite with
five reboots, and a final exact freeze pass with zero kernel alerts. Deployment
report SHA-256 is
`c9f0cd2ca293a1929481296d1c82b1d5a2e26fdc00d5f9a60e56db440e2c6723`,
regression report SHA-256 is
`48d0a71eab8822f06efdf5dfedd379e832a5be7933f8c06a8ebffa6fda63e3e1`,
and final exact report SHA-256 is
`a4c7eb7a509046670982719fdadd8b59ab7539da89562bb58ed59085416db49d`.
The new full image still needs
its separate physical-card acceptance and is not inferred from the raw update.

## Primary Migration: Authenticated Offline App Update

The legacy private key is unavailable, so an automatic old-key-signed bridge
cannot be produced. Existing supported devices instead install the complete
application `2.0.42` archive manually through:

`Settings -> Update -> Offline Update`

The authenticated endpoint is `/api/application/update/offline`. The current
implementation applies safe archive/path validation but does not fetch or
require online metadata for a manually supplied archive. Users must download
the bridge from the exact project release and verify its published SHA-256
before upload.

On the first start of the new binary, the Rust server atomically copies the
production public key and dual-trust policy from `/kvmapp/system/keys` into
`/etc/kvm` before serving HTTP. Files are validated before mutation, keys are
published before policy, file and directory state is synced, unsafe paths are
rejected and the operation is idempotent. `S95nanokvm` enforces the same state
on later starts. The device can then verify new-key-signed app and raw-system
metadata without requiring a second restart.

## Alternatives

- SSH-managed devices may install the complete bridge app or install the new
  public key and dual-trust policy under `/etc/kvm`, then restart the backend.
- Fleets may use the authenticated offline-upload API with per-device
  credentials and exact archive hashes.
- Devices without working web or SSH access must use the new full RC12 SD
  image. It contains app `2.0.42` and the production trust set.
- Enabling unsigned online updates is not an approved migration method.

## Acceptance Gates

1. Two encrypted private-key backups restore to the production public
   fingerprint.
2. Application `2.0.42` archives reproduce exactly.
3. Offline bridge succeeds from published app `2.0.40`/raw.10 and lab app
   `2.0.41`/raw.11 while preserving account, SSH, settings and backend.
4. Historical signed RC11/raw.11 metadata still verifies after the bridge.
5. Production-key test metadata verifies; unknown and policy-excluded IDs fail.
6. RC12 requires app `2.0.42` and signs both metadata kinds with
   `hardened-system-prod-2026q3`.
7. Final A/B, full-SD, signed raw update, recovery and remote-asset gates repeat.
8. Legacy IDs are removed only in a later release after the migration window.
