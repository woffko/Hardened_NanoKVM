/* The hardware generation recorded by S15kvmhwd in /etc/kvm/hw: "alpha",
 * "beta" or "pcie". Header-only so the host test needs no I2C. */
#ifndef HW_VERSION_H
#define HW_VERSION_H

#include <stdio.h>

#define HW_VERSION_ALPHA 0
#define HW_VERSION_BETA 1
#define HW_VERSION_PCIE 2

/* Reads the first byte of the file. A missing, unreadable or empty file, or
 * an unknown letter, means alpha, as the code always assumed; the difference
 * is that nothing is dereferenced or read uninitialized on the way. */
static inline int hw_version_read(const char *path)
{
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        return HW_VERSION_ALPHA;
    }
    int first = fgetc(file);
    fclose(file);
    if (first == 'b') {
        return HW_VERSION_BETA;
    }
    if (first == 'p') {
        return HW_VERSION_PCIE;
    }
    return HW_VERSION_ALPHA;
}

#endif
