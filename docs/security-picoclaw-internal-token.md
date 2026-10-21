# PicoClaw internal capability boundary

This boundary protects NanoKVM-local control requests. It does not limit URLs,
terminal text, Enter, hotkeys or successive HID batches on the target computer.
It is not PicoClaw privilege separation: unrestricted local tools, other state
writers and complete task/session lifetime enforcement remain separate work.

## Request verification and provisioning

Internal authorization requires an actual loopback peer and exactly one
nonempty visible-ASCII header of at most 256 bytes. Missing, duplicate or
malformed headers fail before loading the stored credential. A load error or
malformed stored value denies access. Comparison is constant-time for equal
lengths. Authorization neither provisions nor caches credentials.

The fixed rootfs location is `/etc/kvm/.picoclaw_internal_token`. The loader pins
the directory/file without symlink or mount traversal, requires root ownership,
non-writable-by-others directories, a regular single-link file with mode 0600,
and bounded contents. Legacy visible-ASCII token encodings with outer whitespace
remain readable; this compatibility is not a strength assessment of manually
chosen historical tokens. Empty/control-containing/oversized contents and unsafe
metadata are errors, not a request to silently rotate or repair the token.

Only startup/default configuration may provision a missing credential. It holds
a Config writer permit through the blocking file operation and runtime config
write, including when the initiating HTTP receiver disappears. New tokens use
32 bytes of OS randomness; unavailable entropy fails closed. An anonymous 0600
inode is written and synced before a no-replace link publishes it. The directory
is synced before success. A concurrent existing valid winner is adopted, never
overwritten. There is no path-based or non-atomic fallback if these primitives
are unavailable. Model configuration/default writes share the same permit.

The token is a derived local capability, not a new raw-preserved schema field.
Runtime MCP headers are rewritten by startup/default configuration. Coherence
across raw restore, effective/custom homes and optional-runtime migration still
needs integration and device acceptance. This does not make multi-file PicoClaw
configuration crash-transactional or enroll its profile/workspace/onboard/service
writers. See [state writer inventory](security-state-writers.md).
The runtime JSON/YAML files contain credential copies; their existing
path-based write-then-chmod publication also needs a checked private-file
protocol. Hardening the dedicated token inode does not protect every copy or
establish a filesystem boundary against PicoClaw's still-privileged local tools.

## Shell bridge transport

The control base URL accepts HTTP(S), a hostname/IPv4 or bracketed IPv6 authority,
an optional numeric port and a path. Userinfo, encoded authority, whitespace,
backslashes, query/fragment and malformed ports are rejected. The API prefix must
be a single-rooted path without query/fragment, controls or backslashes. These
rules apply to the control endpoint, not the target `open-url` action payload.

Only parsed `127.0.0.1`, `localhost` and `[::1]` destinations receive the internal
token and the existing local self-signed-TLS exception. `localhost` is pinned to
127.0.0.1 and all loopback control requests bypass proxies. Other explicitly
selected endpoints receive no internal token and retain normal TLS verification.
They still receive the selected PicoClaw session identifier, as before; use only
trusted endpoints. Remote selection does not itself supply web authentication.

All request paths disable curlrc, URL globbing and redirect following. Custom
headers can otherwise be forwarded on redirects; see the
[curl header documentation](https://curl.se/docs/manpage.html#-H).
Session/internal headers use a private 0600 temporary header file instead of
curl arguments. The file is removed on normal completion, curl failure and the
handled shell-exit paths. SIGKILL/power-loss cleanup is not guaranteed. Legacy
environment-token overrides remain accepted but are removed from the child
environment; protected token-file provisioning is the preferred production path.

## Verification scope

Run the focused Rust tests and shell transport suite:

```sh
cargo test --manifest-path server-rust/Cargo.toml --locked --offline --lib \
  --features sandbox-test-fixture picoclaw -- --include-ignored --nocapture
make test-picoclaw-bridge-boundary
make test-state-writer-inventory
```

Rust fixtures use temporary directories and synthetic credentials, never the
actual fixed-root token. They cover malformed/duplicate/missing headers, local
and remote peers, read-only missing lookup, unsafe file types/links/modes,
size bounds, legacy formats, deletion without cached authority and concurrent
creators. Shell fixtures collect actual arguments/header files and exercise a
real redirect, proxy environment and curlrc against local-only HTTP servers.
They also check runtime-session discovery, JSON/binary requests, curl failure,
legacy overrides, header injection rejection and unrestricted target URL/Enter.

These are host/component results. They do not prove target curl/BusyBox/HTTPS
behavior, fixed-root namespace/fault-injection or power-loss acceptance, complete
authenticated-router behavior, raw migration, H2 isolation or C1 closure.
