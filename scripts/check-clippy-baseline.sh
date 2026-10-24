#!/usr/bin/env bash
# Clippy against the tracked baseline: all targets with the sandbox test
# fixture, warnings reduced to a set keyed by lint, message, file and the
# primary span's text (line numbers do not matter), compared with
# scripts/clippy-baseline.tsv. A warning that is not in the baseline fails the
# check; a baseline entry that no longer appears is reported so the baseline
# can be tightened (pass --update to rewrite the baseline from this run).
set -uo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT" || exit 2
BASELINE=scripts/clippy-baseline.tsv
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT
cargo clippy --manifest-path server-rust/Cargo.toml --locked --offline --all-targets \
	--features sandbox-test-fixture --message-format=json > "$LOG" 2>/dev/null
echo "clippy_exit=$?"
python3 -I - "$LOG" "$BASELINE" "${1:-}" <<'PY'
import json, sys
log, baseline_path, mode = sys.argv[1:4]
errors = 0
current = set()
for line in open(log):
    try:
        item = json.loads(line)
    except ValueError:
        continue
    if item.get("reason") != "compiler-message":
        continue
    message = item["message"]
    if message.get("level") == "error":
        errors += 1
    if message.get("level") != "warning" or not message.get("code"):
        continue
    span = next((s for s in message.get("spans", []) if s.get("is_primary")), None)
    text = ""
    if span and span.get("text"):
        text = span["text"][0].get("text", "").strip()
    current.add((message["code"]["code"], message["message"], span["file_name"] if span else "", text))
if mode == "--update":
    with open(baseline_path, "w") as out:
        for key in sorted(current):
            out.write("\t".join(key) + "\n")
    print(f"baseline rewritten: {len(current)} warnings")
    sys.exit(1 if errors else 0)
baseline = set()
for line in open(baseline_path):
    line = line.rstrip("\n")
    if line:
        baseline.add(tuple(line.split("\t", 3)))
new = sorted(current - baseline)
gone = sorted(baseline - current)
print(f"errors: {errors} warnings: {len(current)} baseline: {len(baseline)} new: {len(new)} gone: {len(gone)}")
for key in new:
    print("NEW ", " | ".join(key))
for key in gone:
    print("GONE", " | ".join(key))
sys.exit(1 if errors or new else 0)
PY
