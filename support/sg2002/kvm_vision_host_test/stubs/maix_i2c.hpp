#pragma once
#include "maix_basic.hpp"

namespace maix::peripheral::i2c {
enum class Mode { MASTER, SLAVE };

class I2C {
public:
    I2C(int id, Mode mode);
    int writeto(int address, const uint8_t *data, int length);
    Bytes *readfrom(int address, int length);
};
} // namespace maix::peripheral::i2c
