// Host test for the byte count of an uncompressed image. The capture path
// hands 4:2:0 frames to the image class, whose size table holds 1.5 bytes per
// pixel for them: a count formed with that factor rounded down makes every
// captured frame fail its size check.
#include "maix_image_size.hpp"

#include <cstdio>

using maix::image::uncompressed_bytes;

static int failures = 0;

static void expect(int width, int height, float factor, bool ok, int bytes, const char *what)
{
    int got = -1;
    const bool result = uncompressed_bytes(width, height, factor, &got);
    if (result != ok || (ok && got != bytes)) {
        std::fprintf(stderr, "image size test: %s: %dx%d at %.2f gave %s %d, expected %s %d\n", what, width,
                     height, static_cast<double>(factor), result ? "ok" : "refused", got, ok ? "ok" : "refused",
                     bytes);
        failures++;
    }
}

int main()
{
    // What the capture path uses: NV21 frames at the supported resolutions.
    expect(1920, 1080, 1.5f, true, 3110400, "1080p 4:2:0 frame");
    expect(1280, 720, 1.5f, true, 1382400, "720p 4:2:0 frame");
    expect(640, 480, 1.5f, true, 460800, "480p 4:2:0 frame");
    // Whole factors.
    expect(1920, 1080, 3.0f, true, 6220800, "1080p RGB888");
    expect(1920, 1080, 4.0f, true, 8294400, "1080p RGBA8888");
    expect(640, 480, 1.0f, true, 307200, "grayscale");
    // Fractions below one, and a fractional result cut off as before.
    expect(640, 480, 0.75f, true, 230400, "6-bit Bayer");
    expect(3, 3, 1.5f, true, 13, "odd 4:2:0 size");
    // Refused: no pixels, no factor, a result of no bytes, and overflow.
    expect(0, 1080, 1.5f, false, 0, "zero width");
    expect(1920, -1, 1.5f, false, 0, "negative height");
    expect(1920, 1080, 0.0f, false, 0, "format without a size");
    expect(1, 1, 0.75f, false, 0, "less than one byte");
    expect(46341, 46341, 1.0f, false, 0, "more than an int holds");
    expect(32768, 32768, 4.0f, false, 0, "overflow of the 32-bit product");
    expect(1, 2147479551, 1.0f, true, 2147479551, "largest count with room for the allocation slack");
    expect(1, 2147479552, 1.0f, false, 0, "no room for the allocation slack");
    if (failures != 0)
        return 1;
    std::puts("image size test: PASS");
    return 0;
}
