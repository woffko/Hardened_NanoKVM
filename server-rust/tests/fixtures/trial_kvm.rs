//! Host startup fixture only. No video/HID/device acceptance is provided.
#![no_std]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn kvmv_init(_: u8) {}
#[no_mangle]
pub extern "C" fn kvmv_deinit() {}
#[no_mangle]
pub extern "C" fn kvmv_hdmi_control(enabled: u8) -> u8 {
    enabled
}
#[no_mangle]
pub extern "C" fn set_h264_gop(_: u8) {}
#[no_mangle]
pub extern "C" fn set_frame_detact(_: u8) {}
#[no_mangle]
pub extern "C" fn kvmv_read_img(
    _: u16,
    _: u16,
    _: u8,
    _: u16,
    _: *mut *mut u8,
    _: *mut u32,
) -> i32 {
    -1
}
#[no_mangle]
pub extern "C" fn free_kvmv_data(_: *mut *mut u8) -> i32 {
    0
}
