# Base-system SBOM and advisory triage

Dated triage of the shipped base system against published advisories. It is
a reading of upstream and distribution sources on the date given, bound to
the options this image is built with; it is not a scan of a running device.
Repeat it before every candidate and record the date.

## 2026-10-23, Buildroot 2026.05.1 (security tree), vendor kernel 5.10.265

Toolchain: musl 1.2.6, GCC 14.4.0, binutils 2.45.1. Board patches live under
`buildroot-external/hardened-sg2002/board/sg2002/patches/<package>/<version>/`
and Buildroot applies them after its own (`BR2_GLOBAL_PATCH_DIR`).

| Component | Shipped | Patches carried | Advisories after the shipped version, and whether they reach this image | Action |
| --- | --- | --- | --- | --- |
| OpenSSH | 10.5 (2026-08-11); server+client, sandbox, `UsePAM no` | – | 10.6 (2026-10-06) fixes: sshd compression (LZ77 side channel, inflation past the packet limit), the `restrict` keyword on tunnel forwarding, `Match` blocks overriding options with `none`, GSSAPI state, sftp client path validation, `$`/`\` in client usernames. The image sets no `Compression`, so sshd accepted compression by default; it ships no `authorized_keys` with `restrict`, no `Match` blocks and no GSSAPI. | `Compression no` added to the shipped `sshd_config` (checked by `scripts/test-latest-buildroot-security-policy.sh`). Move to 10.6 with the next Buildroot refresh. |
| OpenSSL | 3.6.3 (2026-06-09) | board: CVE-2026-54876 (OCSP response leak, from 3.6.4) | 3.6.4 (2026-08-25): CMS key unwrap overflow, CMP, QUIC, DTLS, RPK server NULL, empty-ciphertext AEAD tag. 3.6.5 (2026-09-29): DTLS retransmission (High), QUIC, CMP, SM2 timing, EC scalar-multiplication timing (CVE-2026-54872), `SSL_set_SSL_CTX` out-of-bounds. QUIC is built out (`# BR2_PACKAGE_LIBOPENSSL_ENABLE_QUIC is not set`); CMS, CMP, DTLS and SM2 are used by none of sshd, hostapd, wpa_supplicant, curl or ntpd here. The generic EC timing issue is the one item that can touch sshd and TLS handshakes on this CPU. | Move libopenssl to 3.6.5 with the refresh and drop the board OCSP patch then. If the refresh slips, backport CVE-2026-54872. |
| hostapd | 2.12 | – | w1.fi 2026-1 (multi-link, needs `CONFIG_IEEE80211BE`: not built), 2026-5 (RADIUS Message-Authenticator, 2026-08-17: `CONFIG_NO_RADIUS=y`, no RADIUS options in the shipped configuration). | None now; 2.12.1 with the refresh. |
| wpa_supplicant | 2.11 | board: upstream de5e73a0 (2026-2, PMKSA entry must match network context and AKMP) | w1.fi 2026-2 (all versions; a misbehaving AP can make the station use a PMKSA of another configured network; needs credentials for one network) → patched. 2026-3 (SAE H2E NULL dereference: `CONFIG_SAE` not built) and 2026-4 (mesh: not built) do not apply; 2026-1 needs `CONFIG_IEEE80211BE` (not built). | Patched; 2.12 with the refresh. |
| BusyBox (rootfs) | 1.38.0 | Buildroot 0001–0011; board 0012–0014 (CVE-2026-38753/38754/38755), board 0015 (CVE-2026-88833 and its DHCPv6 twin) | 1.38.0 already contains the udhcpc6 fixes 42202bf/d368f3f (CVE-2026-29004; Debian lists 1.38.0 as affected, but the fix text is present: the upstream patch reverse-applies) and the tar hardlink fix 3fb6b31c (CVE-2026-26157/26158). Open upstream as of this date: CVE-2026-88833 (udhcpc raw packet: the claimed IP length is not re-checked; LAN-adjacent DoS of the DHCP client) → board 0015, which also closes the same pattern in `d6_recv_raw_packet`; CVE-2026-38752 (awk `evaluate()` stack overflow by a crafted script: awk here runs only shipped scripts); CVE-2026-88840/88830 (the wget TLS client: used only against `127.0.0.1` by S95); CVE-2026-88838 (mount by a non-root user: no such users); CVE-2026-88839 (passwd/group parsing: local); httpd and dpkg issues (not built). | Board 0015 shipped. Watch upstream for the awk and wget fixes; refresh when 1.38.1 or 1.39 lands. |
| udhcpc6 (app, `/kvmapp/system/bin`) | BusyBox 1.38.0, one static applet (see `docs/udhcpc6-build.md`) | the same 15 patches | As above; rebuilt with board 0015 (SHA-256 `5974eec5f28a0bf0cfa4162e97a993984c3cbf20c67362740f05ec14024488e8`). | Done. |
| avahi | 0.8 | Buildroot 0001–0017 | CVE-2025-68276, -68468, -68471 and CVE-2026-34933 (all denial of service, local D-Bus or LAN mDNS) correspond by title to Buildroot patches 0013–0017 (record browsers with wide-area off, the two assertion fixes, loop detection, conflicting publish flags). The daemon runs with the shipped `avahi-daemon.conf` limits. | None now; confirm the patch-to-CVE mapping against the upstream commits at the refresh. |
| expat | 2.8.2 (2026-06-25) | – | 2.8.4 fixes CVE-2026-76956/76957 (use-after-free) and CVE-2026-66046 (`storeAtts`). The only consumer is avahi, which parses the root-owned service files under `/etc/avahi/services`; no untrusted XML reaches it. | 2.8.4 with the refresh. |
| libcurl / curl | 8.21.0 (2026-06-24) | – | 8.22.0 fixes 21 further issues including CVE-2026-92392 (HTTP/2 upload use-after-free, High). No shipped script or service uses curl (the backend downloads with its own client; S95 probes with BusyBox wget); it is an operator tool. | 8.22.0 with the refresh. |
| musl | 1.2.6 | Buildroot 0003 (iconv, CVE-2026-6042), 0004–0006 (qsort, CVE-2026-40200) | Both 2026 issues are covered by the carried patches. | None. |
| ntp | 4.2.8p18 | Buildroot 0001–0007 (0004 fixes the ntpd crash on a bind failure; a board copy of that change was dropped on 2026-10-24) | No 2026 advisory names 4.2.8p18. | None. |
| Linux | vendor 5.10.265 | the repository's backports | kernel.org 5.10.y is at 5.10.272 (2026-10-15). Read on 2026-10-23 (the changelogs of 5.10.266, 5.10.267, 5.10.270 and 5.10.271 were read only in part): the delta carries network-stack memory-safety fixes reachable by packets this device receives — `ipv6: fix use-after-free in ip6_finish_output2()`, `ipv4: reject undersized MTUs in ip_do_fragment()` and `inet: frags: publish queues before arming timer` (5.10.267); `inet: frags: strip GSO state from fragments before reassembly` (a panic an unprivileged sender can cause, 5.10.268); `ipv6: mcast: fix use-after-free when processing MLD queries`, `ipv4: igmp: fix potential UAF`, `xfrm`/`ipvs` fixes (5.10.269); `tcp: fix corruption of urgent data on multi-segment retransmit`, `netfilter: nf_tables: move hardware offload step after building the chain blob` (5.10.270); `ipv6: do not let ipv6_find_hdr() return an offset past the packet end`, `netfilter: ip6t_rt: fix zero-address non-strict match out-of-bounds read`, `net: arp: terminate device name before lookup`, `vlan`/`llc` headroom fixes (5.10.271); `ipv4: free inet_opt and ireq_opt after an RCU grace period`, `ipv4: validate checksum_start before completing checksum` (5.10.272). USB gadget functions used here (configfs, f_hid, f_mass_storage, uvc) have no fixes in the range; `usbfs` and the storage/NFC/Bluetooth/HID-device fixes do not apply (not built or no such device). | Rebuild the vendor 5.10 kernel with the stable 5.10.266–272 patches in its own maintenance step (not coupled to the app fixes, requirement 7 of the handoff); until then the device relies on the firewall (closed inbound by default) and the local-network trust it already assumes. Finish the partial changelog reads before that rebuild. |
| Other | e2fsprogs 1.47.4, util-linux 2.41 (+3 Buildroot patches), eudev 3.2.14, iproute2 7.0.0, iptables 1.8.11, kmod 34.2, libnl 3.12.0, libevent 2.1.13, zlib 1.3.2, libcap 2.78, iputils 20250605 | as listed in the Buildroot tree | Not searched individually on this date; none exposes a network listener here. | Include in the next dated pass. |

Not in the base image: Tailscale (installed on demand; `scripts/verify-tailscale-package-signature.py` pins a package by Tailscale's own signature chain), dnsmasq, dropbear, chrony, Python.

Sources read on 2026-10-23: openssh.org release notes (10.5, 10.6); openssl-library.org vulnerabilities; w1.fi/security 2026-1…2026-5; the Debian security tracker for busybox (CVE-2026-29004, -26157, -26158, -38752, -88833); curl.se vuln-8.21.0; kernel.org releases; Buildroot 2026.05.1 `package/*/` patch lists; the distribution trackers for avahi, expat and musl where the upstream page gave no version range. Where only secondary sources were found (expat 2.8.4, the avahi patch-to-CVE mapping, the Debian status of CVE-2026-29004 against 1.38.0), the table says so.

## 2026-10-24 refresh of the Buildroot security source

Version bumps as Buildroot backport patches 0004–0008 in
`buildroot-external/hardened-sg2002/buildroot-patches/2026.05.1/`, pinned by
`scripts/prepare-buildroot-2026.05.1-security-source.sh` and required by
`scripts/test-latest-buildroot-security-policy.sh`:

| Package | From | To | Source hash confirmed by |
| --- | --- | --- | --- |
| libopenssl | 3.6.3 + board OCSP patch | 3.6.5 | upstream `openssl-3.6.5.tar.gz.sha256`; Buildroot master |
| openssh | 10.5p1 | 10.6p1 | release-10.6 notes (base64 SHA256 → hex); Buildroot master; Fedora |
| expat | 2.8.2 | 2.9.0 (2.8.4's fixes plus CVE-2026-102633, 32-bit only) | Buildroot master (SHA-256); Alpine (SHA-512) |
| libcurl | 8.21.0 | 8.23.0 | PGP signature, key 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2; Buildroot master; Fedora |
| wpa_supplicant | 2.11 + board PMKSA patch | 2.12 | PGP signature, key EC4AA0A991A5F2464582D52D2B6EF432EFC895FA; Buildroot master; Gentoo |

The board patches `libopenssl/3.6.3/0001-CVE-2026-54876…` and
`wpa_supplicant/2.11/0001-…PMKSA…` are removed: both fixes are in the new
versions. Buildroot's own libopenssl patches apply to 3.6.5 unchanged; its two
wpa_supplicant 2.11 patches are obsolete in 2.12 and the preparation script
removes them, as upstream master did. The refreshed source tree is prepared
as `build/latestbuildroot/buildroot-2026.05.1-raw11-security-r2`; the device
runs the 2026-10-23 set until a rootfs is built from it and accepted.
