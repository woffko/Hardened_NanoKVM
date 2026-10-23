#pragma once
// Host test stand-in for the vendor API that kvm_vision.cpp uses. Calls can
// fail the way the vendor code does: by throwing (see vendor_faults.hpp).
#include <cstddef>
#include <cstdint>
#include <string>

namespace maix {
struct Bytes {
    uint8_t *data = nullptr;
    size_t data_len = 0;
};

namespace err {
enum Err { ERR_NONE = 0, ERR_RUNTIME = 1 };
void check_raise(Err code, const std::string &message);
} // namespace err

namespace time {
void sleep_ms(uint64_t ms);
uint64_t time_ms();
} // namespace time

namespace app {
bool need_exit();
} // namespace app

namespace sys {}
namespace peripheral {}

namespace image {
enum Format { FMT_RGB888 = 0, FMT_YVU420SP = 1 };

class Image {
public:
    Image(int width, int height, Format format);
    Image(const Image &) = delete;
    Image &operator=(const Image &) = delete;
    ~Image();
    void *data() const;
    int data_size() const;
    int width() const;
    int height() const;
    Format format() const;
    Image *to_jpeg(int quality);

private:
    int w;
    int h;
    Format fmt;
    int size;
    uint8_t *bytes;
};
} // namespace image
} // namespace maix
