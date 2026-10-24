# Rust and web dependency advisories

Review date: 2026-10-24, on the remediation branch at commit `93fd810` and
later. This records the audit state and one lockfile change, not an accepted
device update or a published release. The Rustls update of 2026-10-21 has its
own record in [`security-rustls-maintenance.md`](security-rustls-maintenance.md);
the base system (Buildroot packages, kernel) is covered by
[`security-base-system-sbom.md`](security-base-system-sbom.md).

## How the state was measured

- `cargo audit` in `server-rust/` against the RustSec advisory database at
  commit `21d909e4c8bd` (2026-10-24), yanked-package checks on.
- `pnpm audit --prod` in `web/` through `corepack`, against the npm
  advisory service, for the production dependency set of the web interface.

Re-run both before a candidate build and keep the output with the release
evidence; neither replaces the base-system SBOM or a device acceptance.

## Lockfile change

The server lockfile updates exactly two packages; no manifest, feature or
other version changes.

| Package | Previous | Selected | Registry archive SHA-256 |
| --- | --- | --- | --- |
| tokio | 1.52.3 | 1.54.1 | `b52fd3255258d26fac7264ab5a76b53c13367136dc011d3d6ad4f8ed070396a3` |
| spin | 0.9.8 | 0.9.9 | `3763264f6b73151db08c50ff20d7d8a0b8796e021cdea7ceedad07b80155fa0e` |

Verification on the changed lock: every target builds, Clippy stays at the
branch's 25-warning baseline with the same set, `cargo fmt` is clean, and
the full test suite passes (1407 tests, split-by-IO-load run, umask 077).

## Advisory coverage

| Advisory | Package | Applicability and decision |
| --- | --- | --- |
| [RUSTSEC-2026-0386](https://rustsec.org/advisories/RUSTSEC-2026-0386.html) | tokio 1.52.3 | The safe `AsyncFd` constructors accept any `AsRawFd`, an I/O-safety unsoundness. This code base uses no `AsyncFd`. Updated to 1.54.1 anyway, so the lock holds no advised version. |
| yanked crate | spin 0.9.8 | Pulled by `multer` through `axum`; 0.9.8 is yanked on crates.io without an advisory. Updated to 0.9.9. |
| [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html) | crypto-bigint 0.5.5 | Constant-time violations in subtraction, zero counting, division, Montgomery multiplication and limb equality. Reached only through `webrtc 0.17.1 → dtls 0.17.1 → p256 / p384 → elliptic-curve 0.13`, which pins crypto-bigint 0.5; the fix exists only in 0.7.6 and later, so no lockfile change can take it. Exposure: the ECDSA/ECDH keys of a WebRTC DTLS session. The backend creates no long-lived WebRTC certificate, so webrtc-rs generates a per-connection key; a timing side channel could at most target that session's key from the same network path during the session. **Residual, low.** Revisit when webrtc-rs moves to a RustCrypto stack on crypto-bigint 0.7 or later. |
| [RUSTSEC-2024-0449](https://rustsec.org/advisories/RUSTSEC-2024-0449.html) | unsafe-libyaml 0.2.11 | Unmaintained, behind `serde_yaml`. Unchanged; replacing the YAML stack is an owner decision recorded in the remediation ledger (DEP-yaml). |

The earlier Rustls advisories (RUSTSEC-2026-0285, -0346, -0347, -0348, -0349)
are no longer reported: the lock holds rustls 0.23.46.

## Web interface

`pnpm audit --prod` reports no advisories. The twelve `axios` advisories of
the audit stage are gone since the axios update of this branch. Development
dependencies are not part of the shipped package and are not claimed here.
