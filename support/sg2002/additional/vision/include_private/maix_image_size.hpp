#pragma once

#include <climits>

namespace maix::image
{
    /**
     * Bytes of an uncompressed image, or false when the result is not a
     * positive count that leaves room for the allocator's page of slack.
     *
     * bytes_per_pixel is the entry of fmt_size, which is a fraction for the
     * subsampled and packed formats: 1.5 for the 4:2:0 family that the
     * capture path delivers, 0.75 for 6-bit Bayer. It must not be rounded to
     * a whole number before the multiplication. The product is formed in
     * double, where every count that fits an int is exact, and a fractional
     * result is cut off as the plain int arithmetic before it did.
     */
    inline bool uncompressed_bytes(int width, int height, float bytes_per_pixel, int *bytes)
    {
        if (width <= 0 || height <= 0 || !(bytes_per_pixel > 0))
            return false;
        const double total = static_cast<double>(width) * static_cast<double>(height) *
                             static_cast<double>(bytes_per_pixel);
        if (!(total >= 1) || total > static_cast<double>(INT_MAX - 0x1000))
            return false;
        *bytes = static_cast<int>(total);
        return true;
    }
}
