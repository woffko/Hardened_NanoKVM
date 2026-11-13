################################################################################
#
# hardened-sg2002-codec-firmware
#
################################################################################

HARDENED_SG2002_CODEC_FIRMWARE_VERSION = 1e339b782642ce1b2c8aa81f9fdef212912a6a83
HARDENED_SG2002_CODEC_FIRMWARE_SITE = $(call github,0x754C,sg2002_codec_fw,$(HARDENED_SG2002_CODEC_FIRMWARE_VERSION))
HARDENED_SG2002_CODEC_FIRMWARE_SOURCE = sg2002_codec_fw-$(HARDENED_SG2002_CODEC_FIRMWARE_VERSION).tar.gz
HARDENED_SG2002_CODEC_FIRMWARE_LICENSE = PROPRIETARY
HARDENED_SG2002_CODEC_FIRMWARE_REDISTRIBUTE = NO

define HARDENED_SG2002_CODEC_FIRMWARE_INSTALL_TARGET_CMDS
	$(INSTALL) -d $(TARGET_DIR)/usr/share/fw_vcodec
	cp -a $(@D)/. $(TARGET_DIR)/usr/share/fw_vcodec/
	rm -f $(TARGET_DIR)/usr/share/fw_vcodec/.files-list* \
		$(TARGET_DIR)/usr/share/fw_vcodec/.stamp_* \
		$(TARGET_DIR)/usr/share/fw_vcodec/.applied_patches_list
endef

$(eval $(generic-package))
