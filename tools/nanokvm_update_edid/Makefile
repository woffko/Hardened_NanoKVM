# The committed binary is built with the MaixCDK Xuantie toolchain; the same
# command gives the same bytes from any directory.
TOOLCHAIN ?= $(HOME)/MaixCDK/dl/extracted/toolchains/maixcam/host-tools/gcc/riscv64-linux-musl-x86_64
CROSS_COMPILE = $(TOOLCHAIN)/bin/riscv64-unknown-linux-musl-
KVM_INCLUDE = ../../support/sg2002/additional/kvm/include

CFLAGS += -I$(TOOLCHAIN)/sysroot/usr/include -I$(KVM_INCLUDE) -march=rv64gc

CC = $(CROSS_COMPILE)gcc

SRC = nanokvm_update_edid.c

TARGET = nanokvm_update_edid

all: $(TARGET)

$(TARGET): $(SRC) nanokvm_update_edid.h $(KVM_INCLUDE)/i2c_bus_lock.h
	$(CC) $(CFLAGS) -o $@ $(SRC)

clean:
	rm -f $(TARGET)

.PHONY: all clean
