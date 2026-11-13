#!/bin/sh
set -eu

usage() {
	echo "usage: $0 <system-libz.so.1.3.2> <libprotobuf.so>" >&2
	exit 1
}

[ "$#" -eq 2 ] || usage
SYSTEM_ZLIB=$1
PROTOBUF=$2

[ -f "$SYSTEM_ZLIB" ] || {
	echo "missing system zlib: $SYSTEM_ZLIB" >&2
	exit 1
}
[ -f "$PROTOBUF" ] || {
	echo "missing protobuf library: $PROTOBUF" >&2
	exit 1
}
command -v readelf >/dev/null 2>&1 || {
	echo "readelf is required" >&2
	exit 1
}

readelf -h "$SYSTEM_ZLIB" | grep -Fq 'Machine:                           RISC-V' || {
	echo "system zlib is not RISC-V" >&2
	exit 1
}
readelf -h "$PROTOBUF" | grep -Fq 'Machine:                           RISC-V' || {
	echo "protobuf library is not RISC-V" >&2
	exit 1
}
readelf -d "$SYSTEM_ZLIB" | grep -Fq 'Library soname: [libz.so.1]' || {
	echo "system zlib has the wrong SONAME" >&2
	exit 1
}
readelf -d "$PROTOBUF" | grep -Fq 'Shared library: [libz.so.1]' || {
	echo "protobuf no longer declares the expected zlib dependency" >&2
	exit 1
}

for symbol in deflate deflateEnd deflateInit2_ inflate inflateEnd inflateInit2_; do
	readelf -Ws "$PROTOBUF" | awk -v symbol="$symbol" \
		'$7 == "UND" && $8 == symbol { found = 1 } END { exit found ? 0 : 1 }' || {
		echo "protobuf no longer has the reviewed undefined zlib symbol: $symbol" >&2
		exit 1
	}
	readelf -Ws "$SYSTEM_ZLIB" | awk -v symbol="$symbol" \
		'$7 != "UND" && $8 == symbol { found = 1 } END { exit found ? 0 : 1 }' || {
		echo "system zlib does not export required symbol: $symbol" >&2
		exit 1
	}
done

printf 'system zlib satisfies vendor protobuf ABI: PASS\n'
