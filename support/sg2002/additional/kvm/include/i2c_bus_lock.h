/* The shared lock of the LT6911 I2C bus (/dev/i2c-4). Three programs talk to
 * the HDMI chip: libkvm's detection thread (every poll), the EDID tool (its
 * whole update) and S15kvmhwd's probes (flock(1) around i2cdetect). All of
 * them take flock(2) on the bus device node, which needs no lock file and is
 * released when the holder closes the descriptor or dies. The kernel's own
 * driver access is not covered. Header-only, for the C tool and the C++
 * library alike. */
#ifndef I2C_BUS_LOCK_H
#define I2C_BUS_LOCK_H

#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>

#ifndef I2C_BUS_LOCK_PATH
#define I2C_BUS_LOCK_PATH "/dev/i2c-4"
#endif

/* A descriptor to lock on, separate from the one the bus transactions use.
 * Opening the device read-only touches no bus address. */
static inline int i2c_bus_lock_open(const char *path)
{
    return open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
}

/* Take the lock, retrying every 10 ms for up to wait_ms. Returns 0 when held,
 * -1 with errno set otherwise (EWOULDBLOCK when it stayed busy). */
static inline int i2c_bus_lock_acquire(int fd, unsigned wait_ms)
{
    struct timespec step = {0, 10 * 1000 * 1000};
    unsigned waited = 0;

    for (;;) {
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno != EWOULDBLOCK || waited >= wait_ms) {
            return -1;
        }
        nanosleep(&step, NULL);
        waited += 10;
    }
}

static inline int i2c_bus_lock_release(int fd)
{
    return flock(fd, LOCK_UN);
}

#endif /* I2C_BUS_LOCK_H */
