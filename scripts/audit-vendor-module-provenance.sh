#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VENDOR_SDK_DIR="${HARDENED_SG2002_VENDOR_SDK_DIR:-/home/w0w/Hardened_NanoKVM/build/vendor/LicheeRV-Nano-Build}"
ROOTFS_IMAGE="${MODULE_PROVENANCE_ROOTFS_IMAGE:-$ROOT_DIR/build/latestbuildroot/sg2002-config-2026.05.1-raw10/images/rootfs.ext2}"
BASELINE_DIR="${KERNEL_BASELINE_OUTPUT_DIR:-$ROOT_DIR/build/latestbuildroot/kernel-baseline-5.10.4-v2}"
SOURCE_MEDIA_DIR="${SOURCE_BUILT_MEDIA_MODULE_DIR:-$ROOT_DIR/build/latestbuildroot/source-built-media-modules-5.10.4-v2}"
VENDOR_ROOTFS_IMAGE="${VENDOR_MODULE_ROOTFS_IMAGE:-$VENDOR_SDK_DIR/install/soc_sg2002_licheervnano_sd/rawimages/rootfs.sd}"
VENDOR_MODULE_SOURCE_DIR="${VENDOR_MODULE_SOURCE_DIR:-$ROOT_DIR/build/latestbuildroot/vendor-runtime-source-media-v1/system/ko}"
KERNEL_STRIP="${KERNEL_MODULE_STRIP:-$VENDOR_SDK_DIR/host-tools/gcc/riscv64-linux-musl-x86_64/bin/riscv64-unknown-linux-musl-strip}"
OUTPUT_DIR="${MODULE_PROVENANCE_OUTPUT_DIR:-$ROOT_DIR/build/latestbuildroot/module-provenance-raw10-v5}"
REPORT_DIR="$OUTPUT_DIR/report"

require_command() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "required command is missing: $1" >&2
		exit 1
	}
}

for command in debugfs find modinfo sha256sum sort
do
	require_command "$command"
done

for path in "$ROOTFS_IMAGE" "$BASELINE_DIR" "$SOURCE_MEDIA_DIR" \
	"$VENDOR_ROOTFS_IMAGE" "$VENDOR_MODULE_SOURCE_DIR" "$KERNEL_STRIP"
do
	[ -e "$path" ] || {
		echo "required module provenance input is missing: $path" >&2
		exit 1
	}
done

if [ -e "$OUTPUT_DIR" ]; then
	echo "refusing to overwrite module provenance output: $OUTPUT_DIR" >&2
	exit 1
fi

mkdir -p "$REPORT_DIR"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nanokvm-module-provenance.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM
EXTRACT_DIR="$TMP_DIR/rootfs-modules"
mkdir -p "$EXTRACT_DIR"
debugfs -R "rdump /mnt/system/ko $EXTRACT_DIR" "$ROOTFS_IMAGE" >/dev/null 2>&1

if [ -d "$EXTRACT_DIR/ko" ]; then
	EXTRACTED_KO_DIR="$EXTRACT_DIR/ko"
else
	EXTRACTED_KO_DIR="$EXTRACT_DIR"
fi

MANIFEST="$REPORT_DIR/module-provenance.tsv"
printf 'module\tclassification\tnormalization\tsha256\tvermagic\tlicense\tsrcversion\tdepends\tmatched_build_path\truntime_source_path\tsource_candidates\n' > "$MANIFEST"

total=0
baseline_count=0
media_count=0
retained_count=0
source_candidate_count=0
source_unresolved_count=0

module_field() {
	field="$1"
	module="$2"
	modinfo -F "$field" "$module" 2>/dev/null | tr '\t\r\n' '   ' | sed 's/[[:space:]][[:space:]]*/ /g; s/^ //; s/ $//'
}

source_candidates_for_build() {
	module_build="$1"
	module_objects="${module_build%.ko}.mod"
	[ -f "$module_objects" ] || return 0

	for object in $(cat "$module_objects")
	do
		for extension in c cc cpp
		do
			candidate="${object%.o}.$extension"
			if [ -f "$candidate" ]; then
				printf '%s\n' "${candidate#"$VENDOR_SDK_DIR"/}"
				break
			fi
		done
	done | LC_ALL=C sort -u | paste -sd ';' -
}

while IFS= read -r module
do
	total=$((total + 1))
	relative="${module#"$EXTRACTED_KO_DIR"/}"
	name="$(basename "$module")"
	stem="${name%.ko}"
	sha256="$(sha256sum "$module" | awk '{print $1}')"
	classification=""
	normalization="exact"
	matched_build_path=""
	matched_build_file=""
	runtime_source_path=""

	baseline_name_match="$(find "$BASELINE_DIR" -type f -name "$name" ! -path '*/modules/*' -print -quit)"
	if [ -n "$baseline_name_match" ]; then
		baseline_sha256="$(sha256sum "$baseline_name_match" | awk '{print $1}')"
		if [ "$sha256" != "$baseline_sha256" ]; then
			normalized_module="$TMP_DIR/normalized-$name"
			cp "$baseline_name_match" "$normalized_module"
			"$KERNEL_STRIP" --strip-unneeded "$normalized_module"
			normalized_sha256="$(sha256sum "$normalized_module" | awk '{print $1}')"
			[ "$sha256" = "$normalized_sha256" ] || {
				echo "clean baseline module differs after pinned strip transform: $relative" >&2
				exit 1
			}
			normalization="pinned-strip-unneeded"
		fi
		classification="clean-baseline-in-tree"
		matched_build_path="${baseline_name_match#"$ROOT_DIR"/}"
		baseline_count=$((baseline_count + 1))
	else
		media_name_match="$SOURCE_MEDIA_DIR/$name"
		if [ -f "$media_name_match" ]; then
			media_sha256="$(sha256sum "$media_name_match" | awk '{print $1}')"
			[ "$sha256" = "$media_sha256" ] || {
				echo "source-built media module hash mismatch: $relative" >&2
				exit 1
			}
			classification="source-built-media"
			matched_build_path="${media_name_match#"$ROOT_DIR"/}"
			media_count=$((media_count + 1))
		else
			classification="retained-vendor-module"
			retained_count=$((retained_count + 1))

			while IFS= read -r candidate
			do
				[ -n "$candidate" ] || continue
				candidate_sha256="$(sha256sum "$candidate" | awk '{print $1}')"
				if [ "$sha256" = "$candidate_sha256" ]; then
					matched_build_file="$candidate"
					normalization="exact"
					break
				fi

				normalized_candidate="$TMP_DIR/retained-normalized-$total.ko"
				cp "$candidate" "$normalized_candidate"
				"$KERNEL_STRIP" --strip-unneeded "$normalized_candidate"
				normalized_sha256="$(sha256sum "$normalized_candidate" | awk '{print $1}')"
				if [ "$sha256" = "$normalized_sha256" ]; then
					matched_build_file="$candidate"
					normalization="pinned-strip-unneeded"
					break
				fi
			done < <(
				find "$VENDOR_SDK_DIR/linux_5.10" "$VENDOR_SDK_DIR/osdrv" \
					-type f -name "$name" -print 2>/dev/null
			)

			[ -n "$matched_build_file" ] || {
				echo "retained module has no matching SDK build output: $relative" >&2
				exit 1
			}
			matched_build_path="${matched_build_file#"$VENDOR_SDK_DIR"/}"
		fi
	fi

	while IFS= read -r candidate
	do
		[ -n "$candidate" ] || continue
		candidate_sha256="$(sha256sum "$candidate" | awk '{print $1}')"
		if [ "$sha256" = "$candidate_sha256" ]; then
			runtime_source_path="${candidate#"$ROOT_DIR"/}"
			break
		fi
	done < <(find "$VENDOR_MODULE_SOURCE_DIR" -type f -name "$name" -print)

	[ -n "$runtime_source_path" ] || {
		echo "rootfs module does not match frozen vendor runtime source: $relative" >&2
		exit 1
	}

	source_candidates=""
	if [ "$classification" = "retained-vendor-module" ]; then
		source_candidates="$(source_candidates_for_build "$matched_build_file")"
		if [ -n "$source_candidates" ]; then
			source_candidate_count=$((source_candidate_count + 1))
		else
			source_candidates="unresolved"
			source_unresolved_count=$((source_unresolved_count + 1))
		fi
	fi

	vermagic="$(module_field vermagic "$module")"
	license="$(module_field license "$module")"
	srcversion="$(module_field srcversion "$module")"
	depends="$(module_field depends "$module")"

	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$relative" "$classification" "$normalization" "$sha256" "$vermagic" "$license" \
		"$srcversion" "$depends" "$matched_build_path" "$runtime_source_path" \
		"$source_candidates" >> "$MANIFEST"
done < <(find "$EXTRACTED_KO_DIR" -type f -name '*.ko' | LC_ALL=C sort)

[ "$total" -gt 0 ] || {
	echo "no kernel modules found in accepted rootfs" >&2
	exit 1
}
[ "$total" -eq $((baseline_count + media_count + retained_count)) ]

cat > "$REPORT_DIR/summary.md" <<EOF
# Raw.10 kernel-module provenance inventory

- accepted rootfs: \`$ROOTFS_IMAGE\`
- frozen vendor rootfs source: \`$VENDOR_ROOTFS_IMAGE\`
- frozen vendor rootfs SHA-256:
  \`$(sha256sum "$VENDOR_ROOTFS_IMAGE" | awk '{print $1}')\`
- total installed modules: **$total**
- byte-exact clean baseline in-tree modules: **$baseline_count**
- hardware-accepted source-built media modules: **$media_count**
- retained vendor modules still requiring independent rebuild proof: **$retained_count**
- retained modules mapped through SDK build outputs and \`.mod\` source objects: **$source_candidate_count**
- retained modules with unresolved source-object mapping: **$source_unresolved_count**

Every module matches the frozen runtime staging extracted from the pinned
vendor raw rootfs, with the accepted source-built media replacements applied.
Clean baseline in-tree modules may differ before packaging only by the exact
pinned Xuantie \`strip --strip-unneeded\` transform recorded in the manifest.
The mutable vendor \`install/.../rootfs/\` directory is deliberately not a
provenance source because it can change after later SDK builds. This inventory
does not treat a matching vendor binary or a same-name source file as rebuild
proof. Retained modules are mapped through matching SDK build outputs and their
Kbuild \`.mod\` object lists, but still require an independent clean rebuild.
Only the clean baseline and source-built-media classifications currently have
independent build evidence.
EOF

sha256sum "$MANIFEST" > "$REPORT_DIR/SHA256SUMS"
cat "$REPORT_DIR/summary.md"
printf 'module provenance report: %s\n' "$REPORT_DIR/summary.md"
