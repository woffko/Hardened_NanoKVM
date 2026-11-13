// Host test program for i2c_bus_lock.h. "hold PATH MS" takes the lock at
// once, keeps it for MS milliseconds and exits without releasing it. "try
// PATH WAIT_MS" waits up to WAIT_MS for the lock and prints "held" or "busy".
#include "i2c_bus_lock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 4) {
        return 2;
    }
    int fd = i2c_bus_lock_open(argv[2]);
    if (fd < 0) {
        perror("open");
        return 2;
    }
    long ms = atol(argv[3]);
    if (strcmp(argv[1], "hold") == 0) {
        if (i2c_bus_lock_acquire(fd, 0) != 0) {
            puts("busy");
            return 1;
        }
        puts("held");
        fflush(stdout);
        struct timespec pause = {ms / 1000, (ms % 1000) * 1000000L};
        nanosleep(&pause, NULL);
        // Exit holding the lock: the kernel releases it with the descriptor.
        return 0;
    }
    if (strcmp(argv[1], "try") == 0) {
        if (i2c_bus_lock_acquire(fd, (unsigned)ms) != 0) {
            puts("busy");
            return 1;
        }
        puts("held");
        i2c_bus_lock_release(fd);
        return 0;
    }
    return 2;
}
