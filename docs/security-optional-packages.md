# Optional package pins

Tailscale and picoclaw are not part of the image. The web UI installs them on
request, and the backend then downloads exactly one release file for each. The
file's size and SHA-256 are constants in the backend source (`PACKAGE` in
`server-rust/src/api/tailscale.rs` and `server-rust/src/api/picoclaw.rs`), so
they ship inside the signed app. Nothing fetched at install time changes what
is accepted. A hash served next to a package comes from the same origin, so
none is fetched.

`system::package_download::fetch` runs curl with `--proto =https
--proto-redir =https` and with `--max-filesize` set to the pinned size. It then
hashes the file on a blocking thread and removes it unless the digest matches.
A failed transfer also leaves no file. There is no wget fallback (BusyBox wget
in RC12 has no HTTPS) and no other transport.

| Package | Release file | Size | SHA-256 |
| --- | --- | --- | --- |
| Tailscale 1.104.2 | `https://pkgs.tailscale.com/stable/tailscale_1.104.2_riscv64.tgz` | 37991456 | `1f8065e0d966a607ec013c31da09ced55943e4de17cd2e520c9cb8e22f6d3f62` |
| picoclaw v0.2.8 | `https://cdn.sipeed.com/nanokvm/resources/picoclaw/v0.2.8/picoclaw_Linux_riscv64.tar.gz` | 20825810 | `acfa68d48a573e3805762fecbae99c9f495de19707e58ba43933657db55707ae` |

How each pin was checked on 2026-10-23:

- Tailscale: with Tailscale's own signature chain (`clientupdate/distsign`).
  The root keys come from Tailscale's source at tag v1.104.2
  (`clientupdate/distsign/roots/*.pem`). One of them, `crawshaw-root.pem`,
  signs the signing key bundle `https://pkgs.tailscale.com/distsign.pub`. Its
  signing key signs BLAKE2s-256 of the package followed by the package length
  (`.tgz.sig`). The SHA-256 equals the server's `.tgz.sha256`, which is not
  relied on.
- picoclaw: two independent copies are byte-identical. Sipeed's CDN copy has
  the SHA-256 that GitHub reports for the v0.2.8 release asset of
  `sipeed/picoclaw`, and the release's `picoclaw_0.2.8_checksums.txt` lists the
  same value. The CDN's own `sha512.txt` matches too, but the device no longer
  reads it.

## Updating a pin

A new pin is a source change. It reaches devices only in a signed app
release. A device installs the pinned release, never a newer one.

Tailscale:

1. Download `tailscale_<version>_riscv64.tgz` and its `.sig` from
   `https://pkgs.tailscale.com/stable/`. Download `distsign.pub` and
   `distsign.pub.sig` from `https://pkgs.tailscale.com/`.
2. Take the root keys from Tailscale's source at the same release tag:
   `clientupdate/distsign/roots/*.pem`.
3. Run `scripts/verify-tailscale-package-signature.py ROOTS distsign.pub
   distsign.pub.sig PACKAGE PACKAGE.sig`. It prints the size and SHA-256 to pin
   only when both signatures verify.

picoclaw: download the release asset from Sipeed's CDN and from the GitHub
release. Pin it only when both are identical and match the release's published
SHA-256.

The manual steps shown after a failed Tailscale install still link to
Tailscale's latest static package. Installing by hand is the owner's own
choice and does not go through this check.
