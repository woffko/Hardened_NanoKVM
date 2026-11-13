#!/bin/sh
set -eu

usage() {
	echo "usage: $0 <buildroot-pkg-stats.json> <grype-vex.json>" >&2
	exit 1
}

[ "$#" -eq 2 ] || usage
PKG_STATS=$1
GRYPE_VEX=$2

for file in "$PKG_STATS" "$GRYPE_VEX"; do
	[ -f "$file" ] || {
		echo "missing security evidence: $file" >&2
		exit 1
	}
done
command -v jq >/dev/null 2>&1 || {
	echo "jq is required" >&2
	exit 1
}

target_summary="$(jq -r '
  [.packages | to_entries[] | select(any(.value.infras[]; .[0] == "target"))] as $p |
  [
    ($p | length),
    ([$p[].value.cves[]] | length),
    ([$p[].value.cves[]] | unique | length),
    ([$p[].value.unsure_cves[]] | length),
    ([$p[] | select(.value.cpeid == null)] | length)
  ] | @tsv
' "$PKG_STATS")"
[ "$target_summary" = "47	1	1	0	19" ] || {
	echo "unexpected Buildroot target security summary: $target_summary" >&2
	exit 1
}

remaining="$(jq -r '
  [.packages | to_entries[] |
    select(any(.value.infras[]; .[0] == "target")) |
    .key as $package | .value.cves[] | "\($package):\(.)"] |
  sort | join(",")
' "$PKG_STATS")"
[ "$remaining" = "avahi:CVE-2025-59529" ] || {
	echo "unexpected residual Buildroot CVE set: $remaining" >&2
	exit 1
}

grype_summary="$(jq -r '[(.matches | length), (.ignoredMatches | length)] | @tsv' "$GRYPE_VEX")"
[ "$grype_summary" = "0	5" ] || {
	echo "unexpected Grype VEX summary: $grype_summary" >&2
	exit 1
}

vex_ids="$(jq -r '
  [.ignoredMatches[] |
    select(any(.appliedIgnoreRules[]; .namespace == "vex")) |
    .vulnerability.id] | sort | join(",")
' "$GRYPE_VEX")"
[ "$vex_ids" = "CVE-2026-14456,CVE-2026-38753,CVE-2026-38754,CVE-2026-38755,CVE-2026-54876" ] || {
	echo "unexpected Grype VEX-filtered set: $vex_ids" >&2
	exit 1
}

printf 'raw.11 generated security evidence: PASS\n'
