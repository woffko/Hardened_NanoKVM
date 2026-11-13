################################################################################
#
# hardened-cvitek-riscv64-musl-sysroot
#
################################################################################

HARDENED_CVITEK_RISCV64_MUSL_SYSROOT_VERSION = fb0a6ac7409fb477c5f46ced75bf05527def7cb9
HARDENED_CVITEK_RISCV64_MUSL_SYSROOT_SITE = $(call github,0x754C,cvitek-riscv64-musl-sysroot,$(HARDENED_CVITEK_RISCV64_MUSL_SYSROOT_VERSION))
HARDENED_CVITEK_RISCV64_MUSL_SYSROOT_SOURCE = cvitek-riscv64-musl-sysroot-$(HARDENED_CVITEK_RISCV64_MUSL_SYSROOT_VERSION).tar.gz
HARDENED_CVITEK_RISCV64_MUSL_SYSROOT_LICENSE = PROPRIETARY
HARDENED_CVITEK_RISCV64_MUSL_SYSROOT_REDISTRIBUTE = NO

define HARDENED_CVITEK_RISCV64_MUSL_SYSROOT_INSTALL_TARGET_CMDS
	cp -a $(@D)/. $(TARGET_DIR)/
	rm -f $(TARGET_DIR)/.files-list*
endef

$(eval $(generic-package))
