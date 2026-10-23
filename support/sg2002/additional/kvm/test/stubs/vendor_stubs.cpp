#include "kvm_mmf.hpp"
#include "maix_camera.hpp"
#include "maix_i2c.hpp"
#include "vendor_faults.hpp"

#include <chrono>
#include <cstdlib>
#include <stdexcept>
#include <thread>

namespace vendor_faults {
std::atomic<bool> set_resolution{false};
std::atomic<bool> hmirror{false};
std::atomic<bool> close{false};
std::atomic<bool> sleep{false};
std::atomic<bool> venc_add{false};
std::atomic<int> close_calls{0};
std::atomic<int> shell_commands{0};
} // namespace vendor_faults

static void fail_if(const std::atomic<bool> &fault, const char *what)
{
    if (fault.load()) {
        throw std::runtime_error(what);
    }
}

namespace maix {
namespace err {
void check_raise(Err code, const std::string &message)
{
    if (code != ERR_NONE) {
        throw std::runtime_error(message);
    }
}
} // namespace err

namespace time {
void sleep_ms(uint64_t ms)
{
    fail_if(vendor_faults::sleep, "sleep");
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

uint64_t time_ms()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}
} // namespace time

namespace app {
bool need_exit() { return false; }
} // namespace app

namespace image {
Image::Image(int width, int height, Format format)
    : w(width), h(height), fmt(format), size(width * height * 3 / 2),
      bytes(new uint8_t[size]())
{
}
Image::~Image() { delete[] bytes; }
void *Image::data() const { return bytes; }
int Image::data_size() const { return size; }
int Image::width() const { return w; }
int Image::height() const { return h; }
Format Image::format() const { return fmt; }
Image *Image::to_jpeg(int) { return new Image(w, h, fmt); }
} // namespace image

namespace camera {
Camera::Camera(int, int, image::Format) {}
int Camera::restart(int, int, image::Format) { return 0; }
int Camera::set_resolution(int, int)
{
    fail_if(vendor_faults::set_resolution, "set resolution");
    return 0;
}
int Camera::hmirror(int)
{
    fail_if(vendor_faults::hmirror, "horizontal mirror");
    return 0;
}
int Camera::vflip(int) { return 0; }
image::Image *Camera::read() { return new image::Image(640, 480, image::FMT_YVU420SP); }
void Camera::close()
{
    vendor_faults::close_calls++;
    fail_if(vendor_faults::close, "camera close");
}
} // namespace camera

namespace peripheral::i2c {
I2C::I2C(int, Mode) {}
int I2C::writeto(int, const uint8_t *, int) { return 0; }
Bytes *I2C::readfrom(int, int) { return nullptr; }
} // namespace peripheral::i2c
} // namespace maix

int mmf_add_venc_channel(int, mmf_venc_cfg_t *) { return vendor_faults::venc_add.load() ? -1 : 0; }
int mmf_del_venc_channel(int) { return 0; }
int mmf_invert_format_to_mmf(int format) { return format; }
int mmf_venc_push(int, uint8_t *, int, int, int) { return 0; }
int mmf_venc_pop(int, mmf_stream_t *) { return -1; }
int mmf_venc_free(int) { return 0; }
int mmf_enc_jpg_deinit(int) { return 0; }
int mmf_try_deinit(bool) { return 0; }

// No shell command runs on the host: the code under test calls system() for
// GPIO export, state files, init scripts and even a reboot.
extern "C" int system(const char *)
{
    vendor_faults::shell_commands++;
    return 0;
}
