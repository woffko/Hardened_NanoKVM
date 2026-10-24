# Host-side tests

`scripts/run-host-tests.sh` runs every `scripts/test-*` that needs no device
on the current tree and prints one line per test: `PASS`, `FAIL` (with the
last lines of its output) or `NOT TESTED` with the reason. Device, physical
and published-asset tests are always `NOT TESTED` here; they are device
acceptance. The run exits non-zero only on a `FAIL`, and the summary line
counts `NOT TESTED` separately so a release record cannot read it as a pass.
The runner sets `umask 077` itself: the fixtures stage private files in a
directory that must be mode 0700 (`check_private_root`), and a temporary
directory created under `umask 022` is 0755, so those tests fail for that
reason alone.

Three init-script tests exercise the real daemons in private namespaces and
need host builds of the versions the rootfs ships; without them the runner
lists the test as `NOT TESTED` instead of skipping it silently:

| Input | Test | Source |
| --- | --- | --- |
| `XTABLES_BIN_DIR` | `test-s40firewall.sh` | legacy iptables 1.8.11 built from the Buildroot tarball; set `S40FIREWALL_TEST_IPV4_ONLY=1` where `ip6_tables` cannot be loaded (the IPv6 half is then `NOT TESTED`) |
| `NTPD_BIN`, `NTPQ_BIN` | `test-s49ntp.sh` | ntp 4.2.8p18 host build |
| `SSHD_BIN`, `SSH_KEYGEN_BIN` | `test-s50sshd.sh` | OpenSSH host build |

The four `server-rust/scripts/test-*.sh` bound-image tests (embedded app
recovery and restore runtime bytes, the app and native bootstrap root
fixtures) need the linked RV64 backend and the static helpers of the same
build; they read those files as data, never execute them, and rebuild the
host test library with the bound-test feature, which takes a few minutes.
Without the linked build they are `NOT TESTED`.

The web tree's typecheck (`tsc`), lint (`eslint`) and production build
(`vite build`) run with the toolchain pinned in `web/node_modules`; without
it they are `NOT TESTED`. The one pre-existing `react-hooks/exhaustive-deps`
warning in the update page is a warning, not a failure.

`test-ssh-runtime-build-script.py` needs the compiled Cargo build script and
the static RV64 helpers of the last linked build; the runner finds both under
`server-rust/target` after `server-rust/scripts/build-linked-libkvm.sh` and
accepts `NANOKVM_HOST_BUILD_SCRIPT` and `NANOKVM_HOST_HELPER_DIR` instead.

A sweep on 2026-10-24 found two tests that had failed silently for days
because nothing ran them together: the build-security fixture still carried
the pre-refresh OpenSSH 10.5 recipe, and the Picoclaw routing checks still
expected the pre-broker-job onboarding and removal. Run the runner before a
candidate build and keep its log with the release evidence.

## The Rust half of G1

`scripts/run-rust-tests.sh` runs every test of `server-rust` exactly once,
split by IO load: phase 1 runs all targets at 16 threads and skips the
fsync-heavy `native_owner::broker::ipc` module; phase 2 runs that module alone
at 4 threads with backtraces on; then the doctests. The build happens first
and is flushed, because the writeback of a fresh debug build starved fixture
fsyncs in the first minute of a run. The script sets `umask 077` itself (about
93 tests fail under `022`) and prints each phase's exit status and duration;
`RUST_TESTS_PRESSURE_LOG` records an IO-pressure sample every 30 s next to the
log. A run takes 20–30 minutes; one G1 record is one log.

`scripts/check-clippy-baseline.sh` runs Clippy on the same targets and
compares the warning set (keyed by lint, message, file and the primary span's
text, so line numbers do not matter) with `scripts/clippy-baseline.tsv`, the
25 pre-existing warnings. A warning outside the baseline fails the check;
entries that disappeared are listed, and `--update` rewrites the baseline
after they are fixed.
