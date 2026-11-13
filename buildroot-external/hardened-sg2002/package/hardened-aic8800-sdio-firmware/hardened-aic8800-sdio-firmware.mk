################################################################################
#
# hardened-aic8800-sdio-firmware
#
################################################################################

HARDENED_AIC8800_SDIO_FIRMWARE_VERSION = c56f910044cc854d6c553bcb9a644f3bca5a4c38
HARDENED_AIC8800_SDIO_FIRMWARE_SITE = $(call github,lxowalle,aic8800-sdio-firmware,$(HARDENED_AIC8800_SDIO_FIRMWARE_VERSION))
HARDENED_AIC8800_SDIO_FIRMWARE_SOURCE = aic8800-sdio-firmware-$(HARDENED_AIC8800_SDIO_FIRMWARE_VERSION).tar.gz
HARDENED_AIC8800_SDIO_FIRMWARE_LICENSE = PROPRIETARY
HARDENED_AIC8800_SDIO_FIRMWARE_REDISTRIBUTE = NO

define HARDENED_AIC8800_SDIO_FIRMWARE_INSTALL_TARGET_CMDS
	$(INSTALL) -d $(TARGET_DIR)/usr/lib/firmware/aic8800_sdio
	cp -a $(@D)/. $(TARGET_DIR)/usr/lib/firmware/aic8800_sdio/
	rm -f $(TARGET_DIR)/usr/lib/firmware/aic8800_sdio/.files-list* \
		$(TARGET_DIR)/usr/lib/firmware/aic8800_sdio/.stamp_* \
		$(TARGET_DIR)/usr/lib/firmware/aic8800_sdio/.applied_patches_list
endef

$(eval $(generic-package))
