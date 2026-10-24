#!/usr/bin/env bash
# Run every host-side test under scripts/ on the current tree and print one
# line per test: PASS, FAIL or NOT TESTED with the reason. Device, physical
# and published-asset tests are listed as NOT TESTED: they are device
# acceptance, not host checks. A missing optional input makes its test
# NOT TESTED, never a silent skip.
#
# Optional inputs:
#   XTABLES_BIN_DIR              host build of legacy iptables 1.8.11 (test-s40firewall)
#   S40FIREWALL_TEST_IPV4_ONLY=1 when ip6_tables cannot be loaded; the IPv6 half is then NOT TESTED
#   NTPD_BIN, NTPQ_BIN           host build of ntp 4.2.8p18 (test-s49ntp)
#   SSHD_BIN, SSH_KEYGEN_BIN     host build of OpenSSH (test-s50sshd)
#   NANOKVM_HOST_BUILD_SCRIPT    compiled Cargo build script (test-ssh-runtime-build-script);
#                                default: the newest server-rust/target/release/build/nanokvm-rust-server-*/build-script-build
#   NANOKVM_HOST_HELPER_DIR      static RV64 helpers of the linked build; default:
#                                server-rust/target/restore-runtime/riscv64gc-unknown-linux-musl/release
#   HOST_TEST_TIMEOUT            seconds per test (default 1200)
#
# Exit status 1 when any test FAILED. NOT TESTED does not fail the run; the
# summary counts it so a release record cannot mistake it for PASS.
set -u
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT" || exit 2
TIMEOUT="${HOST_TEST_TIMEOUT:-1200}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0; not_tested=0; failed=""

device_reason() {
	case $1 in
	test-published-raw-update-via-api|test-published-raw-update-playwright)
		echo "needs a device and a published raw update" ;;
	test-sophgo-media-modules-device|test-raw9-physical-keyboard|test-raw9-physical-paste)
		echo "device/physical test" ;;
	test-latest-buildroot-h264-direct-resume|test-latest-buildroot-remote-syslog|test-latest-buildroot-usb-safe|test-latest-buildroot-watchdog)
		echo "device test (--confirm-device <ip>)" ;;
	esac
}

report() {
	name=$1 code=$2 secs=$3
	if [ "$code" -eq 0 ]; then
		pass=$((pass + 1)); printf 'PASS       %s (%ss)\n' "$name" "$secs"
	else
		fail=$((fail + 1)); failed="$failed $name"
		printf 'FAIL       %s exit=%s (%ss)\n' "$name" "$code" "$secs"
		tail -n 5 "$WORK/$name.out" | sed 's/^/           | /'
	fi
}

skip() {
	not_tested=$((not_tested + 1))
	printf 'NOT TESTED %s: %s\n' "$1" "$2"
}

run() {
	name=$1; shift
	start=$(date +%s)
	timeout "$TIMEOUT" "$@" >"$WORK/$name.out" 2>&1
	report "$name" $? $(( $(date +%s) - start ))
}

echo "host tests on $(git rev-parse --short HEAD 2>/dev/null || echo '?') ($(git status --short 2>/dev/null | wc -l) dirty) $(date -u +%FT%TZ)"

for f in scripts/test-*.sh; do
	n=$(basename "$f" .sh)
	reason=$(device_reason "$n")
	if [ -n "$reason" ]; then skip "$n" "$reason"; continue; fi
	case $n in
	test-s40firewall)
		[ -n "${XTABLES_BIN_DIR:-}" ] || { skip "$n" "set XTABLES_BIN_DIR to a host build of legacy iptables"; continue; } ;;
	test-s49ntp)
		[ -n "${NTPD_BIN:-}" ] && [ -n "${NTPQ_BIN:-}" ] || { skip "$n" "set NTPD_BIN and NTPQ_BIN to a host ntp build"; continue; } ;;
	test-s50sshd)
		[ -n "${SSHD_BIN:-}" ] && [ -n "${SSH_KEYGEN_BIN:-}" ] || { skip "$n" "set SSHD_BIN and SSH_KEYGEN_BIN to a host OpenSSH build"; continue; } ;;
	esac
	run "$n" bash "$f"
done

for f in scripts/test-*.py; do
	n=$(basename "$f" .py)
	if [ "$n" = test-ssh-runtime-build-script ]; then
		build_script="${NANOKVM_HOST_BUILD_SCRIPT:-$(ls -t server-rust/target/release/build/nanokvm-rust-server-*/build-script-build 2>/dev/null | head -n 1)}"
		helpers="${NANOKVM_HOST_HELPER_DIR:-server-rust/target/restore-runtime/riscv64gc-unknown-linux-musl/release}"
		if [ -z "$build_script" ] || [ ! -x "$build_script" ]; then
			skip "$n" "no compiled Cargo build script (build the backend or set NANOKVM_HOST_BUILD_SCRIPT)"; continue
		fi
		if [ ! -f "$helpers/nanokvm-ssh-sandbox" ] || [ ! -f "$helpers/nanokvm-app-recovery" ]; then
			skip "$n" "no static helpers in $helpers (run the linked build or set NANOKVM_HOST_HELPER_DIR)"; continue
		fi
		run "$n" python3 -B "$f" "$build_script" "$helpers/nanokvm-ssh-sandbox" "$helpers/nanokvm-app-recovery" "$helpers"
		continue
	fi
	run "$n" python3 -B "$f"
done

for f in scripts/test-*.cjs; do
	n=$(basename "$f" .cjs)
	reason=$(device_reason "$n")
	if [ -n "$reason" ]; then skip "$n" "$reason"; continue; fi
	run "$n" node "$f"
done

echo "host tests: pass=$pass fail=$fail not_tested=$not_tested${failed:+ failed:$failed}"
[ "$fail" -eq 0 ]
