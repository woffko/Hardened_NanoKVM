#!/usr/bin/env bash
# S15kvmhwd's HDMI chip version detection (L-B12): a chip that does not
# answer is probed again, and a version detected earlier is never replaced by
# "ue". The functions are taken from the script and run under sh and BusyBox
# sh with a stand-in for `flock ... i2cdetect` that answers from a list.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
S15="$ROOT_DIR/kvmapp/system/init.d/S15kvmhwd"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

fail() {
    echo "S15 hdmi version test: $*" >&2
    exit 1
}

for name in kvm_hdmi_version_probe kvm_hdmi_version_detect; do
    awk -v start="$name()" '$0 == start {p = 1} p {print} p && $0 == "}" {exit}' "$S15" >> "$T/lib.sh"
    grep -qx "$name()" "$T/lib.sh" || fail "no function $name in S15kvmhwd"
done

mkdir -p "$T/bin"
# flock /dev/i2c-4 i2cdetect -ry 4 ADDR ADDR: one answer per probe from
# $ANSWERS (space separated; "none" means no chip), consumed in order.
cat > "$T/bin/flock" <<'STUB'
#!/bin/sh
[ "$1" = /dev/i2c-4 ] && [ "$2" = i2cdetect ] || exit 64
addr="$5"
count=$(cat "$COUNT")
echo $((count + 1)) > "$COUNT"
echo "probe $addr" >> "$CALLS"
set -- $ANSWERS
shift "$count" 2>/dev/null || true
answer="${1:-none}"
[ "$answer" = "$addr" ] && echo "40: -- -- ${addr#0x}"
exit 0
STUB
printf '#!/bin/sh\necho "sleep $1" >> "$CALLS"\n' > "$T/bin/sleep"
chmod +x "$T/bin"/*

shells="sh"
command -v busybox >/dev/null 2>&1 && shells="sh busybox"

# run SHELL ANSWERS: ANSWERS is one answer per probe call, "none" for silence.
run() {
    echo 0 > "$T/count"
    : > "$T/calls"
    env PATH="$T/bin:$PATH" ANSWERS="$2" COUNT="$T/count" CALLS="$T/calls" HDMI_VERSION_FILE="$T/hdmi_version" \
        $([ "$1" = busybox ] && echo busybox) sh -c ". '$T/lib.sh'; kvm_hdmi_version_detect" < /dev/null
}
version() {
    cat "$T/hdmi_version" 2>/dev/null || echo absent
}
probes() {
    grep -c '^probe' "$T/calls" || true
}

for shell in $shells; do
    rm -f "$T/hdmi_version"
    run "$shell" "0x2c"
    [ "$(version)" = c ] && [ "$(probes)" = 1 ] || fail "$shell: an answering C chip: $(version), $(probes) probes"
    run "$shell" "none 0x2b 0x44"
    [ "$(version)" = ux ] || fail "$shell: a UXC chip: $(version)"
    run "$shell" "none 0x2b none"
    [ "$(version)" = d ] || fail "$shell: a D chip: $(version)"
    echo "ok $shell: an answering chip is recorded at once"

    # Silent for the first two rounds (two probes each), then a UXC chip.
    rm -f "$T/hdmi_version"
    run "$shell" "none none none none none 0x2b 0x44"
    # Two silent rounds of two probes each, then 0x2c, 0x2b and 0x44: seven.
    # (BusyBox sh runs its own sleep applet, so waits are not counted.)
    [ "$(version)" = ux ] && [ "$(probes)" = 7 ] || fail "$shell: a chip in reset was not probed again: $(version), $(probes) probes"
    echo "ok $shell: a chip that is silent at first is probed again"

    rm -f "$T/hdmi_version"
    run "$shell" "none none none none none none none none none none none"
    [ "$(version)" = ue ] && [ "$(probes)" = 10 ] || fail "$shell: a silent chip with no record: $(version), $(probes) probes"
    echo "ok $shell: a silent chip with no earlier record is ue after five rounds"

    printf 'ux\n' > "$T/hdmi_version"
    run "$shell" "none none none none none none none none none none none"
    [ "$(version)" = "ux" ] || fail "$shell: a silent chip replaced the recorded version: $(version)"
    printf 'ue\n' > "$T/hdmi_version"
    run "$shell" "none none none none none none none none none none none"
    [ "$(version)" = "ue" ] || fail "$shell: ue stays ue: $(version)"
    printf 'ue\n' > "$T/hdmi_version"
    run "$shell" "0x2c"
    [ "$(version)" = c ] || fail "$shell: a chip that answers later replaces ue: $(version)"
    echo "ok $shell: a detected version survives a silent probe; ue does not block a later answer"
done
echo "S15 hdmi version test: PASS"
