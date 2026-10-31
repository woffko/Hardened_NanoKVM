# Version rules shared by the candidate wrappers and the raw packager. Bash.
#
# One number means one build. Numbers in scripts/release-burned-versions.txt are
# used up. Debug builds for device iterations take app 2.0.45 and up with system
# 0.3.0-raw.14 and up, always below the release. Release candidates take app
# 2.1.N with system 0.4.0-raw.N; a candidate that fails acceptance burns its
# numbers and the next one takes the next numbers.

# The oldest system a raw update can restore from. Older systems go through
# this release first.
RELEASE_MINIMUM_SYSTEM=0.3.0-raw.12

# A list that cannot be read proves nothing, so every number counts as used.
release_version_used() {
	local list="${RELEASE_BURNED_VERSIONS:-$ROOT_DIR/scripts/release-burned-versions.txt}"
	[ -r "$list" ] || return 0
	grep -Fxq -- "$1" "$list"
}

# release_check_versions SYSTEM APP: refuses with a message on stderr.
release_check_versions() {
	local system=$1 app=$2 version family
	for version in "$system" "$app"; do
		if release_version_used "$version"; then
			echo "version $version is already used (scripts/release-burned-versions.txt)" >&2
			return 1
		fi
	done
	if [[ "$system" =~ ^0\.4\.0-raw\.([1-9][0-9]*)$ ]]; then
		family=release
	elif [[ "$system" =~ ^0\.3\.0-raw\.([1-9][0-9]*)$ ]] && [ "${BASH_REMATCH[1]}" -ge 14 ]; then
		family=debug
	else
		echo "system version $system is neither 0.3.0-raw.14+ (debug) nor 0.4.0-raw.N (release)" >&2
		return 1
	fi
	if [[ "$app" =~ ^2\.1\.(0|[1-9][0-9]*)$ ]]; then
		[ "$family" = release ] || {
			echo "application $app is a release number, system $system is a debug number" >&2
			return 1
		}
	elif [[ "$app" =~ ^2\.0\.([1-9][0-9]*)$ ]] && [ "${BASH_REMATCH[1]}" -ge 45 ]; then
		[ "$family" = debug ] || {
			echo "application $app is a debug number, system $system is a release number" >&2
			return 1
		}
	else
		echo "application version $app is neither 2.0.45+ (debug) nor 2.1.N (release)" >&2
		return 1
	fi
}
