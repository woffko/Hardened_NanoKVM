#pragma once
// Switches for the host stand-ins: each makes one vendor call throw.
#include <atomic>

namespace vendor_faults {
extern std::atomic<bool> set_resolution;
extern std::atomic<bool> hmirror;
extern std::atomic<bool> close;
extern std::atomic<bool> sleep;
extern std::atomic<bool> venc_add;
extern std::atomic<int> close_calls;
extern std::atomic<int> shell_commands;
} // namespace vendor_faults
