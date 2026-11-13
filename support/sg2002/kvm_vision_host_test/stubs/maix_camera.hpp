#pragma once
#include "maix_basic.hpp"

namespace maix::camera {
class Camera {
public:
    Camera(int width, int height, image::Format format);
    int restart(int width, int height, image::Format format);
    int set_resolution(int width, int height);
    int hmirror(int enable);
    int vflip(int enable);
    image::Image *read();
    void close();
};
} // namespace maix::camera
