#!/bin/sh
set -eu

: "${HARDENED_MCOPY_REAL:?HARDENED_MCOPY_REAL is required}"
exec "$HARDENED_MCOPY_REAL" -m "$@"
