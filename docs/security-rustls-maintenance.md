# Rustls dependency maintenance

Review date: 2026-10-21. This records a source/lockfile change, not an accepted
device update or a published security release.

## Dependency boundary

The Rust server lockfile updates only these two packages:

| Package | Previous | Selected | Registry archive SHA-256 |
| --- | --- | --- | --- |
| rustls | 0.23.41 | 0.23.46 | `48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf` |
| rustls-webpki | 0.103.13 | 0.103.16 | `4443b1b6d39d7c663139942cc4558262562d2c84123bb6282ef177009ca8b281` |

Both downloaded archives match their crates.io index checksums. No manifest,
other package version, provider selection, or TLS configuration is changed.
Rustls remains transitive through tokio-rustls and WebRTC's DTLS dependency;
it does not need a redundant direct dependency. Builds use the committed lockfile
with `--locked`. Both selected packages retain upstream MSRV 1.71; licenses
are Apache-2.0 OR ISC OR MIT for Rustls and ISC for WebPKI.

The resolved host and linked RV64 Rustls features remain `ring,std,tls12`:
no aws-lc, post-quantum, Brotli, or zlib feature is introduced. The HTTPS server still does not request
client certificates. The linked RV64 WebPKI features are `alloc,ring,std`.
Final package bytes must also be checked before release; dependency graphs
and local linked builds are not an installed inventory.

## Advisory coverage

| Advisory | Applicability and change |
| --- | --- |
| [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html) | The old version is affected and the inbound HTTPS handshake is a relevant production path. Rustls 0.23.46 includes the fix. Upstream does not describe an authentication bypass. |
| [RUSTSEC-2026-0346](https://rustsec.org/advisories/RUSTSEC-2026-0346.html) | Custom client-session-store Debug output can disclose session secrets. No such production store was found in the scoped server/DTLS source. Updated anyway. |
| [RUSTSEC-2026-0347](https://rustsec.org/advisories/RUSTSEC-2026-0347.html) | ECH rejection with pre-handshake buffered client data affects 0.23.44/0.23.45, not the old 0.23.41. The chosen 0.23.46 avoids introducing it. |
| [RUSTSEC-2026-0348](https://rustsec.org/advisories/RUSTSEC-2026-0348.html) | The inspected build excludes the vulnerable optional Brotli feature. Updated anyway. |
| [RUSTSEC-2026-0349](https://rustsec.org/advisories/RUSTSEC-2026-0349.html) | No scoped production Rustls client/session-store/PQ-provider trigger was found. DTLS uses Rustls certificate types/verifiers, not its TLS connection state machine. Updated anyway. |
| [WebPKI 0.103.16 distrust update](https://github.com/rustls/webpki/releases/tag/v%2F0.103.16) | Includes rejection of certificate paths containing specified distrusted SPKIs. Applicability depends on the configured trust anchors and verification path; no NanoKVM exploitation is asserted. Do not stop at cached 0.103.14/0.103.15. |

See the [Rustls 0.23.46 release](https://github.com/rustls/rustls/releases/tag/v%2F0.23.46)
and [WebPKI change](https://github.com/rustls/webpki/pull/546) for upstream fixes.
This update does not update curl, OpenSSL, PicoClaw's runtime, the base image,
or certificates trusted by other programs.

## Verification and remaining work

The authenticated-restore test captures a synthetic custom-path TLS identity,
encrypts/decrypts its capsule, validates the archive, writes the canonical test
destination, and uses the production path-based TLS loader and listener. It
requires both TLS 1.2 and TLS 1.3, the original certificate, HTTP/1.1 ALPN and
application-data delivery. It is not an early-boot apply or device test.

The loopback WebRTC compatibility test uses generated WebRTC certificates,
IPv4-only loopback ICE candidates and no STUN/TURN/mDNS. It requires a real
DTLS/SCTP message exchange and awaits closure of both owned peers, including
after exchange errors/timeouts. It is not H.264 playback, connected-browser
revocation, backpressure, or hardware acceptance.

The local offline Cargo audit uses advisory database commit
`5502dedfaf87df1ef64175116bf516640aab2a7c` (2026-10-20). The old lock reports
four Rustls vulnerabilities; the updated lock reports zero numbered
vulnerabilities. `unsafe-libyaml` still has the RUSTSEC-2024-0449 unmaintained
warning. Yanked-package checks were disabled for this offline comparison.

The database's new WebPKI distrust entry still has a placeholder advisory ID,
so its absence from the audit count is not evidence of safety. Its version
requirement was reviewed separately against the upstream release and selected
0.103.16. Cargo's audit output also omits database commit/time metadata; the Git
commit above was inspected separately. This is not a clean full-project audit.

Local verification on the changed source/lockfile:

- 61 selected TLS/restore/app-trial/WebRTC tests passed, including both new
  real-handshake tests. They do not reproduce the upstream vulnerabilities.
- The production main HTTP/HTTPS startup fixture passed its Commit, wrong-Commit
  and disconnect scenarios using a synthetic host libkvm ABI.
- Clippy adds no warnings: the same 30 existing structured warnings remain.
  This is not a strict warning-free result.
- Linked RV64 build and ELF ABI/loader/dependency/hardening inspection passed.
- Exact six-helper binding checks, ten root/bootstrap cases and the frozen
  startup fixture passed. RV64 images are data only in these host fixtures.

Binary-bound candidate SBOM, independent app/full-image builds, device
TLS/WebRTC/update tests and release acceptance remain separate gates. The
broader remediation's unresolved aggregate failure, C1 update-chain work and
H2 local privilege isolation are not closed here. No device was updated.
