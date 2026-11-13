# The official-Buildroot SG2002 tree remains a runtime candidate until its BSP,
# ABI, and recovery gates are complete. Keep current rootfs libraries ahead of
# the isolated vendor runtime paths and validate the result on recoverable media.
export HARDENED_SG2002_PORT_STAGE=runtime-candidate
export PATH="/mnt/system/usr/bin:/mnt/system/usr/sbin:$PATH"
export LD_LIBRARY_PATH="/lib:/usr/lib:/usr/local/lib:/mnt/system/lib:/mnt/system/usr/lib:/mnt/system/usr/lib/3rd${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
