# The bundled DHCPv6 client

`/kvmapp/system/bin/udhcpc6` is the DHCPv6 client that `S30eth` starts in
DHCPv6 mode (`-i eth0 -s /kvmapp/system/network/udhcpc6.script -t 10 -T 1
-A 5 -b -p /run/udhcpc6.eth0.pid`). The rootfs BusyBox (1.38.0) is built
without the `udhcpc6` applet, so the app ships its own.

Until this change the shipped file was a complete BusyBox 1.36.1 multi-call
binary, dynamically linked against the rootfs musl, renamed `udhcpc6`: a shell
and every other applet of that build travelled with it, and the version lagged
the rootfs.

## What ships now

One static applet, built from the same source as the rootfs BusyBox:

- the pinned BusyBox 1.38.0 tarball (SHA-256
  `34f9ea6ff8636f2c9241153b9114eefa9e65674a45318ae1ef95bb5f31c53bb2`),
- the Buildroot 2026.05.1 security tree's `package/busybox` patches and the
  board patches under
  `buildroot-external/hardened-sg2002/board/sg2002/patches/busybox/1.38.0/`,
  applied in name order (15 patches at the time of writing; the board's 0015
  makes both DHCP clients refuse a header length shorter than the IP and UDP
  headers, CVE-2026-88833 and its DHCPv6 twin),
- the fragment `buildroot-external/hardened-sg2002/board/sg2002/udhcpc6.fragment`
  on top of `allnoconfig`: static, `FEATURE_IPV6`, `UDHCPC6` with the RFC 3646
  DNS options the hook reads (`$dns`, `$search`, `$domain`), the hook path as
  the default script, no shell (`SH_IS_NONE`), no IPv4 client or server, no
  `busybox` applet and so no `--help` banner with a build timestamp,
- the Buildroot musl toolchain for riscv64.

The build is reproducible: two builds from these inputs give identical bytes.
The binary is about 90 KiB, statically linked, with no program interpreter and
no dynamic section, so it does not depend on the rootfs libc or BusyBox version.

## Building and checking

`scripts/build-udhcpc6.sh [out dir]` verifies the tarball hash, applies the
patches, builds, and writes `udhcpc6`, the effective `udhcpc6.config` and
`inputs.sha256` (the hashes of every input and the compiler version) to the
output directory (default `build/udhcpc6/`). It expects the local Buildroot
trees under `build/latestbuildroot/`; `BUSYBOX_TARBALL`, `BUILDROOT_TREE` and
`TOOLCHAIN_PREFIX` override them.

`scripts/test-udhcpc6-binary.sh [binary]` checks the committed file (or the
one given) with `readelf` and `strings`: ELF64 RISC-V executable, no
interpreter, no dynamic section, the `udhcpc6` applet name present, no shell
applet or shell strings, no IPv4 client or server, no timestamp banner, size
under 256 KiB; and that the fragment keeps the client static, v6-only and
shell-free. The previous 1.36.1 binary fails these checks. The test does not
execute the client; a DHCPv6 lease on a device is still device acceptance,
and the hook itself is covered by `scripts/test-udhcpc6-script.sh`.

Note on BusyBox's kconfig: it keeps the first assignment of a symbol and
ignores later ones, so the build script replaces each fragment symbol in the
`allnoconfig` output instead of appending the fragment. `UDHCPC6` depends on
`FEATURE_IPV6`; `FEATURE_SYSLOG` has no prompt and is selected only by
applets that need it, and `S30eth` passes no `-S`.
