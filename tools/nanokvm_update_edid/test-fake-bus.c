// Host test model of an LT6911UXC behind the registers that
// nanokvm_update_edid uses, linked instead of /dev/i2c-* (EDID_FAKE_BUS).
//
// Register 0xFF selects the bank. In bank 0x80, data written to 0x59 queues
// in a FIFO, 0x5C/0x5D give the page and offset, and 0x5A starts an action:
// 0x81 erases the flash, 0x90 programs the FIFO (0x5E = 0xC0) or loads a
// read buffer (0x5E = 0x5F), whose bytes are then read from 0x5F. Bank 0x81
// register 0x08 returns the chip ID.
//
// Environment, for the test only:
//   FAKE_FLASH      256-byte file with the initial EDID page (else erased)
//   FAKE_FLASH_OUT  file that receives the EDID page when the bus closes
//   FAKE_LOG        file that receives "erase" and "program" events
//   FAKE_FAIL_AFTER_ERASE  fail the Nth bus write after the first erase, once
//   FAKE_GARBAGE    reads of 0x5F return 0x5A bytes, as a wrong chip might
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define PAGES 2

static uint8_t flash[PAGES][256];
static uint8_t regs[256][256];
static uint8_t bank;
static uint8_t reg_pointer;
static uint8_t fifo[64];
static size_t fifo_len;
static uint8_t read_buffer[32];
static size_t read_len;
static long writes_after_erase = -1;
static int garbage;
static FILE *event_log;

static void event(const char *what, int page, int offset)
{
    if (event_log) {
        fprintf(event_log, "%s %d %d\n", what, page, offset);
        fflush(event_log);
    }
}

int bus_open(void)
{
    const char *path = getenv("FAKE_FLASH");
    memset(flash, 0xFF, sizeof(flash));
    if (path) {
        FILE *file = fopen(path, "rb");
        if (!file || fread(flash[0], 1, 256, file) != 256) {
            fprintf(stderr, "fake bus: cannot read %s\n", path);
            exit(2);
        }
        fclose(file);
    }
    garbage = getenv("FAKE_GARBAGE") != NULL;
    if (getenv("FAKE_LOG")) {
        event_log = fopen(getenv("FAKE_LOG"), "a");
    }
    return 3;
}

static void action(uint8_t value)
{
    int page = regs[0x80][0x5C] == 0x81 ? 1 : 0;
    int offset = regs[0x80][0x5D];
    if (value == 0x81) {
        memset(flash, 0xFF, sizeof(flash));
        event("erase", 0, 0);
        if (writes_after_erase < 0) {
            writes_after_erase = 0;
        }
    } else if (value == 0x90 && regs[0x80][0x5E] == 0xC0) {
        for (size_t i = 0; i < fifo_len && offset + i < 256; i++) {
            flash[page][offset + i] = fifo[i];
        }
        event("program", page, offset);
        fifo_len = 0;
    } else if (value == 0x90 && regs[0x80][0x5E] == 0x5F) {
        memcpy(read_buffer, &flash[page][offset], sizeof(read_buffer));
        read_len = sizeof(read_buffer);
    }
}

ssize_t bus_write(int fd, const void *buf, size_t len)
{
    const uint8_t *data = buf;
    const char *fail = getenv("FAKE_FAIL_AFTER_ERASE");
    (void)fd;
    if (writes_after_erase >= 0 && ++writes_after_erase == (fail ? atol(fail) : 0)) {
        event("fail", 0, 0);
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    reg_pointer = data[0];
    if (len == 1) {
        return 1;
    }
    if (data[0] == 0xFF) {
        bank = data[1];
        return (ssize_t)len;
    }
    if (bank == 0x80 && data[0] == 0x59 && len > 2) {
        size_t n = len - 1 > sizeof(fifo) ? sizeof(fifo) : len - 1;
        memcpy(fifo, data + 1, n);
        fifo_len = n;
        return (ssize_t)len;
    }
    regs[bank][data[0]] = data[1];
    if (bank == 0x80 && data[0] == 0x5A) {
        action(data[1]);
    }
    return (ssize_t)len;
}

ssize_t bus_read(int fd, void *buf, size_t len)
{
    uint8_t *data = buf;
    (void)fd;
    if (bank == 0x81 && reg_pointer == 0x08) {
        memset(data, 0xEE, len);
    } else if (bank == 0x80 && reg_pointer == 0x5F) {
        for (size_t i = 0; i < len; i++) {
            data[i] = garbage ? 0x5A : (i < read_len ? read_buffer[i] : 0);
        }
    } else {
        memset(data, 0, len);
    }
    return (ssize_t)len;
}

int bus_close(int fd)
{
    const char *path = getenv("FAKE_FLASH_OUT");
    (void)fd;
    if (path) {
        FILE *file = fopen(path, "wb");
        if (!file || fwrite(flash[0], 1, 256, file) != 256 || fclose(file) != 0) {
            fprintf(stderr, "fake bus: cannot write %s\n", path);
            exit(2);
        }
    }
    if (event_log) {
        fclose(event_log);
        event_log = NULL;
    }
    return 0;
}
