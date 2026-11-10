################################################################################
#
# hardened-nanokvm-kvmapp
#
################################################################################

HARDENED_NANOKVM_KVMAPP_VERSION = 2.1.4
NANOKVM_KVMAPP_SOURCE_DIR ?= \
	$(abspath $(BR2_EXTERNAL_HARDENED_SG2002_PATH)/../../build/kvmapp-rust/kvmapp)
HARDENED_NANOKVM_KVMAPP_SITE = $(NANOKVM_KVMAPP_SOURCE_DIR)
HARDENED_NANOKVM_KVMAPP_SITE_METHOD = local
HARDENED_NANOKVM_KVMAPP_LICENSE = GPL-3.0-only, PROPRIETARY
HARDENED_NANOKVM_KVMAPP_REDISTRIBUTE = NO
HARDENED_NANOKVM_KVMAPP_DEPENDENCIES = \
	avahi \
	host-python3 \
	hostapd \
	openssh \
	wpa_supplicant

define HARDENED_NANOKVM_KVMAPP_INSTALL_TARGET_CMDS
	test "$$(cat $(@D)/version)" = "$(HARDENED_NANOKVM_KVMAPP_VERSION)"
	cmp $(@D)/server/NanoKVM-Server $(@D)/backends/NanoKVM-Server.rust
	$(HOST_DIR)/bin/python3 $(BR2_EXTERNAL_HARDENED_SG2002_PATH)/../../scripts/ssh-runtime-binding.py \
		inspect --backend $(@D)/server/NanoKVM-Server --quiet
	$(HOST_DIR)/bin/python3 $(BR2_EXTERNAL_HARDENED_SG2002_PATH)/../../scripts/app-recovery-binding.py \
		verify --backend $(@D)/server/NanoKVM-Server \
		--helper $(@D)/system/bin/nanokvm-app-recovery
	$(INSTALL) -d $(TARGET_DIR)/kvmapp $(TARGET_DIR)/etc/kvm \
		$(TARGET_DIR)/etc/init.d $(TARGET_DIR)/mnt/data
	cp -a $(@D)/. $(TARGET_DIR)/kvmapp/
	$(INSTALL) -D -m 0755 $(@D)/system/bin/nanokvm-app-recovery \
		$(TARGET_DIR)/usr/libexec/nanokvm-app-recovery
	for role in owner broker ctl recovery; do \
		$(HOST_DIR)/bin/python3 -B $(BR2_EXTERNAL_HARDENED_SG2002_PATH)/../../scripts/native-runtime-binding.py \
			$$role verify --backend $(@D)/server/NanoKVM-Server \
			--helper $(@D)/system/bin/nanokvm-native-$$role || exit 1; \
		$(INSTALL) -D -m 0755 $(@D)/system/bin/nanokvm-native-$$role \
			$(TARGET_DIR)/usr/libexec/nanokvm-native-$$role || exit 1; \
	done
	rm -f $(TARGET_DIR)/kvmapp/.files-list*
	printf 'rust\n' > $(TARGET_DIR)/etc/kvm/backend
	chmod 0644 $(TARGET_DIR)/etc/kvm/backend
	for name in S00kmod S01fs S01syslogd S02apprecover S02klogd S03usbdev S15kvmhwd \
		S30eth S30wifi S40firewall S49ntp S50avahi-daemon S50sshd \
		S95nanokvm; do \
		script="$(@D)/system/init.d/$$name"; \
		[ -f "$$script" ] || continue; \
		$(INSTALL) -m 0755 "$$script" "$(TARGET_DIR)/etc/init.d/$$name"; \
	done
	rm -f $(TARGET_DIR)/etc/init.d/S02udisk \
		$(TARGET_DIR)/etc/init.d/S04backlight \
		$(TARGET_DIR)/etc/init.d/S05tp \
		$(TARGET_DIR)/etc/init.d/S40bluetoothd \
		$(TARGET_DIR)/etc/init.d/S50ssdpd
	cp -a $(@D)/system/mnt-data/. $(TARGET_DIR)/mnt/data/
	if [ -f $(TARGET_DIR)/mnt/data/sensor_cfg.ini.LT ]; then \
		cp $(TARGET_DIR)/mnt/data/sensor_cfg.ini.LT $(TARGET_DIR)/mnt/data/sensor_cfg.ini; \
	fi
	grep -qE '^[[:space:]]*[^#]+[[:space:]]+/data[[:space:]]+' $(TARGET_DIR)/etc/fstab || \
		printf '/dev/mmcblk0p3\t/data\texfat\tdefaults\t0\t0\n' >> $(TARGET_DIR)/etc/fstab
endef

$(eval $(generic-package))
