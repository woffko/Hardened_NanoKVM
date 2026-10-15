################################################################################
#
# hardened-sg2002-vendor-runtime
#
################################################################################

HARDENED_SG2002_VENDOR_RUNTIME_VERSION = d88d58feca49ef15f4cc7bd1f27dbf17dc25f85e
NANOKVM_VENDOR_RUNTIME_SOURCE_DIR ?= \
	$(abspath $(BR2_EXTERNAL_HARDENED_SG2002_PATH)/../../build/latestbuildroot/vendor-runtime-source-media-v1)
HARDENED_SG2002_VENDOR_RUNTIME_SITE = $(NANOKVM_VENDOR_RUNTIME_SOURCE_DIR)
HARDENED_SG2002_VENDOR_RUNTIME_SITE_METHOD = local
HARDENED_SG2002_VENDOR_RUNTIME_LICENSE = PROPRIETARY
HARDENED_SG2002_VENDOR_RUNTIME_REDISTRIBUTE = NO
HARDENED_SG2002_VENDOR_RUNTIME_DEPENDENCIES = hardened-nanokvm-kvmapp

define HARDENED_SG2002_VENDOR_RUNTIME_INSTALL_TARGET_CMDS
	$(INSTALL) -d $(TARGET_DIR)/mnt/system $(TARGET_DIR)/kvmapp/server/dl_lib $(TARGET_DIR)/lib
	cp -a $(@D)/system/. $(TARGET_DIR)/mnt/system/
	# /mnt/system/usr is an unpruned wholesale carry-forward of the vendor
	# SDK's own userspace (see server-rust/native/README.md). usr/bin is
	# CVITEK sample/test binaries never invoked by anything this image
	# runs. usr/lib duplicates -- by search-path priority, byte-for-byte
	# for 16 files and same-name/size for 6 more -- what dl_lib already
	# ships, plus a handful of genuinely unused extras (unused sensor
	# plugins, raw/sample/replay test libs). The one exception is
	# libsns_lt6911.so: the LT6911 HDMI bridge is this device's one real
	# sensor, and unlike everything else here it has no copy in dl_lib --
	# so it's the only file /mnt/system/usr/lib keeps.
	rm -rf $(TARGET_DIR)/mnt/system/usr/bin
	find $(TARGET_DIR)/mnt/system/usr/lib -type f ! -name libsns_lt6911.so -delete
	find $(TARGET_DIR)/mnt/system/usr/lib -type d -empty -delete
	cp -a $(@D)/kvmapp-dl-lib/. $(TARGET_DIR)/kvmapp/server/dl_lib/
	$(INSTALL) -m 0755 $(NANOKVM_KVMAPP_SOURCE_DIR)/server/dl_lib/libkvm.so \
		$(TARGET_DIR)/kvmapp/server/dl_lib/libkvm.so
	$(INSTALL) -m 0755 $(NANOKVM_KVMAPP_SOURCE_DIR)/server/dl_lib/libkvm_mmf.so \
		$(TARGET_DIR)/kvmapp/server/dl_lib/libkvm_mmf.so
	$(INSTALL) -m 0755 $(@D)/loaders/ld-musl-riscv64xthead.so.1 $(TARGET_DIR)/lib/
	$(INSTALL) -m 0755 $(@D)/loaders/ld-musl-riscv64v0p7_xthead.so.1 $(TARGET_DIR)/lib/
	ln -sf libstdc++.so.6.0.28 $(TARGET_DIR)/kvmapp/server/dl_lib/libstdc++.so.6
	ln -sf libgomp.so.1.0.0 $(TARGET_DIR)/kvmapp/server/dl_lib/libgomp.so.1
	ln -sf libatomic.so.1.2.0 $(TARGET_DIR)/kvmapp/server/dl_lib/libatomic.so.1
	rm -f $(TARGET_DIR)/kvmapp/server/dl_lib/libz.so \
		$(TARGET_DIR)/kvmapp/server/dl_lib/libz.so.1 \
		$(TARGET_DIR)/kvmapp/server/dl_lib/libz.so.1.3
	# libkvm.so no longer declares NEEDED on libopencv_video.so.409 (patched
	# out: verified via exhaustive symbol-set comparison that libkvm.so
	# calls nothing from video, and by extension nothing from its
	# downstream-only deps dnn/calib3d/features2d/flann/protobuf -- see
	# server-rust/native/README.md). Drop the now-unused files rather than
	# ship dead, non-redistributable vendor blobs.
	rm -f $(TARGET_DIR)/kvmapp/server/dl_lib/libopencv_video.so.4.9.0 \
		$(TARGET_DIR)/kvmapp/server/dl_lib/libopencv_video.so.409 \
		$(TARGET_DIR)/kvmapp/server/dl_lib/libopencv_dnn.so.4.9.0 \
		$(TARGET_DIR)/kvmapp/server/dl_lib/libopencv_dnn.so.409 \
		$(TARGET_DIR)/kvmapp/server/dl_lib/libopencv_calib3d.so.4.9.0 \
		$(TARGET_DIR)/kvmapp/server/dl_lib/libopencv_calib3d.so.409 \
		$(TARGET_DIR)/kvmapp/server/dl_lib/libopencv_features2d.so.4.9.0 \
		$(TARGET_DIR)/kvmapp/server/dl_lib/libopencv_features2d.so.409 \
		$(TARGET_DIR)/kvmapp/server/dl_lib/libopencv_flann.so.4.9.0 \
		$(TARGET_DIR)/kvmapp/server/dl_lib/libopencv_flann.so.409 \
		$(TARGET_DIR)/kvmapp/server/dl_lib/libprotobuf.so.32.0.12 \
		$(TARGET_DIR)/kvmapp/server/dl_lib/libprotobuf.so.32
endef

$(eval $(generic-package))
