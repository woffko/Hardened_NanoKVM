#!/bin/sh
# Runs inside fakeroot after Buildroot's permission table, for every image
# format. That table marks BusyBox setuid, and a raw restore refuses a setuid
# shell. Nothing on this system needs it: every service runs as root or drops
# its own privileges.
set -eu
chmod 0755 "$1/bin/busybox"
