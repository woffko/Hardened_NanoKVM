#!/usr/bin/env bash
# Host test for B13: kvm_vision.cpp built with the host compiler against
# vendor stand-ins that throw. No C++ exception may leave its C interface or
# end a worker thread, and vi_mutex must be free afterwards. An optional
# argument names another kvm_vision.cpp to test (for negative controls).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
KVM=$ROOT/support/sg2002/additional/kvm
SOURCE=${1:-$KVM/src/kvm_vision.cpp}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

c++ -std=c++17 -O1 -g -pthread -w \
	-I "$KVM/test/stubs" -I "$KVM/include" \
	"$SOURCE" "$KVM/test/stubs/vendor_stubs.cpp" \
	"$KVM/test/exception_boundary_test.cpp" \
	-o "$WORK/exception_boundary_test"
timeout 60 "$WORK/exception_boundary_test"
