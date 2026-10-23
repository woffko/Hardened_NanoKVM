// Host test for B13: kvm_vision.cpp built against vendor stand-ins that throw.
// No C++ exception may leave its C interface or end a worker thread through
// std::terminate, and vi_mutex must be free afterwards.
#include "kvm_vision.h"
#include "vendor_faults.hpp"

#include <cstdio>
#include <cstdlib>
#include <pthread.h>

extern pthread_mutex_t vi_mutex;
void *vi_subsystem_detection(void *arg);
void *watchdog_sf_feed(void *arg);

static void check(bool condition, const char *what)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", what);
        exit(1);
    }
}

static bool vi_mutex_free()
{
    if (pthread_mutex_trylock(&vi_mutex) != 0) {
        return false;
    }
    pthread_mutex_unlock(&vi_mutex);
    return true;
}

static void read_fails_cleanly(uint16_t width, uint16_t height, uint8_t type, const char *name)
{
    uint8_t byte = 0;
    uint8_t *data = &byte;
    uint32_t size = 1;
    int result = kvmv_read_img(width, height, type, 80, &data, &size);
    check(result == IMG_VENC_ERROR, name);
    check(data == NULL && size == 0, name);
    check(vi_mutex_free(), name);
    printf("ok %s\n", name);
}

int main()
{
    // The worker entry points first, while their stop flag is still clear.
    vendor_faults::sleep = true;
    check(watchdog_sf_feed(NULL) == NULL, "watchdog worker");
    printf("ok a throwing sleep ends the watchdog worker\n");
    check(vi_subsystem_detection(NULL) == NULL, "HDMI detection worker");
    printf("ok a throwing sleep ends the HDMI detection worker\n");
    vendor_faults::sleep = false;

    vendor_faults::set_resolution = true;
    read_fails_cleanly(1280, 720, 0, "a throwing resolution change is a read error");
    vendor_faults::set_resolution = false;

    vendor_faults::venc_add = true;
    read_fails_cleanly(640, 480, 1, "a throwing encoder setup is a read error");
    vendor_faults::venc_add = false;

    vendor_faults::hmirror = true;
    kvmv_init(0);
    check(vi_mutex_free(), "camera setup");
    vendor_faults::hmirror = false;
    printf("ok a throwing camera setup leaves video stopped\n");

    // A second start must not block on a lifecycle lock left held, and its
    // shutdown must survive a throwing camera close.
    kvmv_init(0);
    vendor_faults::close = true;
    kvmv_deinit();
    check(vendor_faults::close_calls == 1, "the camera close was reached");
    check(vi_mutex_free(), "camera shutdown");
    printf("ok a throwing camera close is an incomplete shutdown\n");
    return 0;
}
