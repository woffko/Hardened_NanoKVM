# Wi-Fi AP provisioning key

In Wi-Fi configuration mode, `kvm_system` starts an access point named
`NanoKVM`. One key serves as its WPA2 passphrase and as the `x-ap-key` of the
unauthenticated provisioning API (`POST /api/network/wifi` and `/verify`). The
OLED shows it as text and in two QR codes.

## Key

RC12 drew four digits from `srand(time_ms)` and doubled each one, for 7,290
possible keys. A captured handshake or a short series of API guesses recovered
it.

Each AP session now gets a fresh key from the kernel CSPRNG (`getrandom`): ten
characters from the 31 symbols `2-9` and `a-z` without `i`, `l` and `o`, about
49 bits. Rejection sampling keeps every symbol equally likely. If the random
source fails, the key is cleared, the AP is not started and the OLED shows
"WiFi AP failed"; there is no weaker fallback.

The key is written to `/kvmapp/kvm/ap.pass` with mode 0600 through a fresh
scratch file (`O_EXCL`, `O_NOFOLLOW`), `fsync` and a rename. If that fails,
the AP is not started either. A key left from an earlier session is never
reused: every AP start generates a new one. App updates preserve the file as
before.

The text page shows the key on one 6x8 line (60 of 64 pixels). The URL page
now spreads `<ip>/#/`, `WIFI?P=` and the key over three lines, because the key
and its prefix no longer fit one 4-pixel line together. Both QR codes keep
their format and still fit the fixed QR version 3 at level M (42 bytes): the
join code takes 36 bytes and the URL code at most 39.

## Guessing

The provisioning API allows 5 failed keys per source and 20 shared by all
sources, each for 10 minutes; see [backend-api-inventory.md](backend-api-inventory.md).

## Still open

These live in `S30wifi`, which is digest-bound in the support catalog. A change
ships only with a support transition or a full image:

- hostapd gets `wpa=2` without `rsn_pairwise=CCMP`, so TKIP is not excluded;
- `/etc/hostapd.conf`, which holds the key, is created with the default mode;
- the AP has no timeout, and open networks have no explicit mode.

A provisioning token separate from the WPA2 passphrase, and the headless or
no-OLED claim channel, are WP-09 owner decisions.

## Verification

`scripts/test-kvm-system-ap-key.py` compiles the generator header for the host
with `-Wall -Wextra -Werror` and checks:

- the length and alphabet of 3,100 keys, with no duplicates and a chi-square
  bound;
- short and interrupted random reads;
- a failing source, which yields no key;
- mode 0600, a planted scratch link that is replaced rather than followed, and
  a failed store that keeps the old file;
- that the AP start no longer uses `srand`/`rand`.

Three negative controls fail as expected: modulo bias, a weak fallback, and the
RC12 generator. The MaixCDK build of `kvm_system` imports `getrandom`, `fchmod`,
`fsync` and `rename`, and no longer imports `srand` or `rand`. The device check
of the OLED pages, QR join and provisioning is still required.
