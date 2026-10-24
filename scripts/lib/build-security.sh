#!/bin/sh

build_file_sha256() {
	if digest_line=$(sha256sum -- "$1"); then
		:
	else
		echo "SHA-256 calculation failed" >&2
		return 1
	fi
	digest_hex=${digest_line%% *}
	case "$digest_hex" in
		'' | *[!0-9a-f]*) echo "invalid SHA-256 output" >&2; return 1 ;;
	esac
	[ "${#digest_hex}" -eq 64 ] || {
		echo "invalid SHA-256 length" >&2
		return 1
	}
	printf '%s\n' "$digest_hex"
}

build_file_sha512_base64() (
	digest_tmp=$(mktemp "${TMPDIR:-/tmp}/nanokvm-sha512.XXXXXX") || exit 1
	trap 'rm -f "$digest_tmp"' 0
	if ! openssl dgst -sha512 -binary -out "$digest_tmp" "$1"; then
		echo "SHA-512 calculation failed" >&2
		exit 1
	fi
	[ "$(wc -c < "$digest_tmp")" -eq 64 ] || {
		echo "invalid SHA-512 length" >&2
		exit 1
	}
	if digest_base64=$(openssl base64 -A -in "$digest_tmp"); then
		:
	else
		echo "SHA-512 encoding failed" >&2
		exit 1
	fi
	[ "${#digest_base64}" -eq 88 ] || {
		echo "invalid SHA-512 encoding length" >&2
		exit 1
	}
	printf '%s\n' "$digest_base64"
)

# Hold one metadata output transaction; callers publish the JSON last.
build_begin_metadata_output() {
	metadata_output=$1
	metadata_lock="$metadata_output.lock"
	metadata_work=
	mkdir "$metadata_lock" || {
		echo "metadata output is already locked: $metadata_output" >&2
		return 1
	}
	trap '[ -z "$metadata_work" ] || rm -rf "$metadata_work"; rmdir "$metadata_lock"' 0
	trap 'exit 130' INT
	trap 'exit 143' TERM
	for metadata_suffix in '' .sha256 .sig .sig.base64; do
		if [ -e "$metadata_output$metadata_suffix" ] || [ -L "$metadata_output$metadata_suffix" ]; then
			echo "refusing to overwrite metadata output: $metadata_output$metadata_suffix" >&2
			return 1
		fi
	done
	metadata_work=$(mktemp -d "$(dirname "$metadata_output")/.nanokvm-metadata.XXXXXX") || return 1
}

build_publish_metadata_output() {
	metadata_hash=$(build_file_sha256 "$metadata_work/metadata.json") || return 1
	printf '%s  %s\n' "$metadata_hash" "$metadata_output" > "$metadata_work/checksum" || return 1
	if [ -n "$SIGNING_KEY" ]; then
		openssl dgst -sha256 -sign "$SIGNING_KEY" \
			-out "$metadata_work/signature" "$metadata_work/metadata.json" || return 1
		[ -s "$metadata_work/signature" ] || return 1
		openssl base64 -A -in "$metadata_work/signature" \
			-out "$metadata_work/signature.base64" || return 1
		[ -s "$metadata_work/signature.base64" ] || return 1
		mv "$metadata_work/signature" "$metadata_output.sig" || return 1
		mv "$metadata_work/signature.base64" "$metadata_output.sig.base64" || return 1
	fi
	mv "$metadata_work/checksum" "$metadata_output.sha256" || return 1
	mv "$metadata_work/metadata.json" "$metadata_output" || return 1
}

# Return failure both for a policy match and for an incomplete inspection.
build_reject_pattern() {
	policy_pattern=$1
	policy_file=$2
	policy_label=$3
	if grep -Eq -- "$policy_pattern" "$policy_file"; then
		echo "forbidden $policy_label in $policy_file" >&2
		return 1
	else
		policy_status=$?
		if [ "$policy_status" -ne 1 ]; then
			echo "cannot inspect $policy_label in $policy_file" >&2
			return 1
		fi
	fi
}

build_assert_no_private_keys() {
	key_scan_root=$1
	[ -d "$key_scan_root" ] || {
		echo "private-key scan root is missing: $key_scan_root" >&2
		return 1
	}
	# Only filenames reach this capture; never print matched key contents.
	if key_scan_matches=$(find -L "$key_scan_root" -type f -exec sh -c '
		for key_scan_file do
			if grep -alE -m 1 -- "-----BEGIN ([[:alnum:]_]+ )*PRIVATE KEY-----" "$key_scan_file"; then
				:
			else
				key_scan_status=$?
				[ "$key_scan_status" -eq 1 ] || exit 2
			fi
		done
	' sh {} +); then
		:
	else
		echo "private-key scan failed: $key_scan_root" >&2
		return 1
	fi
	if [ -n "$key_scan_matches" ]; then
		echo "private-key material is forbidden in $key_scan_root" >&2
		return 1
	fi
}

build_verify_security_recipes() {
	security_source=$1
	grep -qx 'OPENSSH_VERSION_MAJOR = 10.6' "$security_source/package/openssh/openssh.mk" || {
		echo "security source has an unexpected OpenSSH version" >&2
		return 1
	}
	grep -qx 'LIBOPENSSL_VERSION = 3.6.5' "$security_source/package/libopenssl/libopenssl.mk" || {
		echo "security source has an unexpected libopenssl version" >&2
		return 1
	}
	grep -qx 'EXPAT_VERSION = 2.9.0' "$security_source/package/expat/expat.mk" || {
		echo "security source has an unexpected expat version" >&2
		return 1
	}
	grep -qx 'LIBCURL_VERSION = 8.23.0' "$security_source/package/libcurl/libcurl.mk" || {
		echo "security source has an unexpected libcurl version" >&2
		return 1
	}
	grep -qx 'WPA_SUPPLICANT_VERSION = 2.12' "$security_source/package/wpa_supplicant/wpa_supplicant.mk" || {
		echo "security source has an unexpected wpa_supplicant version" >&2
		return 1
	}
	grep -qx 'HOSTAPD_VERSION = 2.12' "$security_source/package/hostapd/hostapd.mk" || {
		echo "security source has an unexpected hostapd version" >&2
		return 1
	}
	build_reject_pattern 'CONFIG_IEEE80211BE' \
		"$security_source/package/hostapd/hostapd.mk" 'hostapd 11be configuration'
}
