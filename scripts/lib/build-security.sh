#!/bin/sh

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
	if key_scan_matches=$(find "$key_scan_root" -type f -exec sh -c '
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
	grep -qx 'OPENSSH_VERSION_MAJOR = 10.5' "$security_source/package/openssh/openssh.mk" || {
		echo "security source has an unexpected OpenSSH version" >&2
		return 1
	}
	grep -qx 'HOSTAPD_VERSION = 2.12' "$security_source/package/hostapd/hostapd.mk" || {
		echo "security source has an unexpected hostapd version" >&2
		return 1
	}
	build_reject_pattern 'CONFIG_IEEE80211BE' \
		"$security_source/package/hostapd/hostapd.mk" 'hostapd 11be configuration'
}
