use std::{
    path::Path,
    slice,
    sync::{LazyLock, Mutex},
    thread,
    time::Duration,
};

#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
use std::{
    env,
    ffi::{CStr, CString},
    os::raw::{c_char, c_int, c_void},
    path::PathBuf,
};

use crate::{AppError, Result};

const HDMI_DISABLE_FILE: &str = "/etc/kvm/hdmi_disable";
#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
const DEFAULT_LIBKVM_PATHS: &[&str] = &[
    "/tmp/server/dl_lib/libkvm.so",
    "/kvmapp/server/dl_lib/libkvm.so",
];
#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
const RTLD_NOW: c_int = 2;

#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
type KvmvInit = unsafe extern "C" fn(u8);
#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
type KvmvReadImg = unsafe extern "C" fn(u16, u16, u8, u16, *mut *mut u8, *mut u32) -> i32;
#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
type FreeKvmvData = unsafe extern "C" fn(*mut *mut u8) -> i32;
#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
type SetH264Gop = unsafe extern "C" fn(u8);
#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
type SetFrameDetect = unsafe extern "C" fn(u8);
#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
type KvmvDeinit = unsafe extern "C" fn();
#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
type KvmvHdmiControl = unsafe extern "C" fn(u8) -> u8;

#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
#[cfg_attr(not(target_env = "musl"), link(name = "dl"))]
unsafe extern "C" {
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
    fn dlerror() -> *const c_char;
}

static VISION: LazyLock<std::result::Result<Mutex<KvmVision>, String>> = LazyLock::new(|| {
    KvmVision::load()
        .map(Mutex::new)
        .map_err(|err| err.to_string())
});

pub fn read_mjpeg(width: u16, height: u16, quality: u16) -> Result<(Vec<u8>, i32)> {
    vision()?
        .lock()
        .map_err(lock_error)?
        .read_img(width, height, 0, quality)
}

pub fn read_h264(width: u16, height: u16, bit_rate: u16) -> Result<(Vec<u8>, i32)> {
    vision()?
        .lock()
        .map_err(lock_error)?
        .read_img(width, height, 1, bit_rate)
}

pub fn set_frame_detect(frame: u8) -> Result<()> {
    vision()?
        .lock()
        .map_err(lock_error)?
        .set_frame_detect(frame);
    Ok(())
}

pub fn set_h264_gop(gop: u8) -> Result<()> {
    vision()?.lock().map_err(lock_error)?.set_h264_gop(gop);
    Ok(())
}

pub fn set_hdmi(enabled: bool) -> Result<u8> {
    Ok(vision()?.lock().map_err(lock_error)?.set_hdmi(enabled))
}

pub fn init() -> Result<()> {
    let _ = vision()?;
    Ok(())
}

fn vision() -> Result<&'static Mutex<KvmVision>> {
    VISION
        .as_ref()
        .map_err(|err| AppError::Internal(format!("failed to initialize libkvm: {err}")))
}

fn lock_error<T>(_: T) -> AppError {
    AppError::Internal("libkvm lock poisoned".to_string())
}

#[cfg(all(target_arch = "riscv64", feature = "linked-libkvm"))]
#[link(name = "kvm")]
unsafe extern "C" {
    fn kvmv_init(debug_info_en: u8);
    fn kvmv_read_img(
        width: u16,
        height: u16,
        kind: u8,
        quality_or_rate: u16,
        data: *mut *mut u8,
        data_size: *mut u32,
    ) -> i32;
    fn free_kvmv_data(data: *mut *mut u8) -> i32;
    #[link_name = "set_h264_gop"]
    fn kvm_set_h264_gop(gop: u8);
    #[link_name = "set_frame_detact"]
    fn kvm_set_frame_detect(frame: u8);
    fn kvmv_deinit();
    fn kvmv_hdmi_control(enabled: u8) -> u8;
}

#[cfg(all(target_arch = "riscv64", feature = "linked-libkvm"))]
struct KvmVision;

#[cfg(all(target_arch = "riscv64", feature = "linked-libkvm"))]
unsafe impl Send for KvmVision {}

#[cfg(all(target_arch = "riscv64", feature = "linked-libkvm"))]
impl KvmVision {
    fn load() -> Result<Self> {
        // SAFETY: Initializes libkvm with logging disabled, matching Go backend.
        unsafe {
            kvmv_init(0);
        }
        let vision = Self;
        vision.initialize_hdmi();
        Ok(vision)
    }

    fn initialize_hdmi(&self) {
        let disabled = Path::new(HDMI_DISABLE_FILE).exists();

        // SAFETY: Mirrors Go backend startup: reset HDMI, wait briefly, then
        // re-enable it unless the persisted disable flag is present.
        unsafe {
            kvmv_hdmi_control(0);
        }
        thread::sleep(Duration::from_millis(10));
        if !disabled {
            // SAFETY: libkvm accepts 0/1 for HDMI state.
            unsafe {
                kvmv_hdmi_control(1);
            }
        }
    }

    fn set_frame_detect(&self, frame: u8) {
        // SAFETY: Direct binding matches server/include/kvm_vision.h.
        unsafe {
            kvm_set_frame_detect(frame);
        }
    }

    fn set_h264_gop(&self, gop: u8) {
        // SAFETY: Direct binding matches server/include/kvm_vision.h.
        unsafe {
            kvm_set_h264_gop(gop);
        }
    }

    fn set_hdmi(&self, enabled: bool) -> u8 {
        // SAFETY: libkvm accepts 0/1 for HDMI state.
        unsafe { kvmv_hdmi_control(u8::from(enabled)) }
    }

    fn read_img(
        &mut self,
        width: u16,
        height: u16,
        kind: u8,
        quality_or_rate: u16,
    ) -> Result<(Vec<u8>, i32)> {
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut len: u32 = 0;

        // SAFETY: libkvm writes an owned buffer pointer and size on success. The
        // pointer is copied into a Vec and released through free_kvmv_data below.
        let result =
            unsafe { kvmv_read_img(width, height, kind, quality_or_rate, &mut ptr, &mut len) };

        if result < 0 {
            return Ok((Vec::new(), result));
        }

        let data = if ptr.is_null() || len == 0 {
            Vec::new()
        } else {
            // SAFETY: ptr/len come from libkvm for this call and remain valid
            // until free_kvmv_data is invoked below.
            unsafe { slice::from_raw_parts(ptr, len as usize).to_vec() }
        };
        // SAFETY: Mirrors the Go backend: release libkvm's output buffer for
        // all non-negative results, including empty/no-change frames.
        unsafe {
            free_kvmv_data(&mut ptr);
        }

        Ok((data, result))
    }
}

#[cfg(all(target_arch = "riscv64", feature = "linked-libkvm"))]
impl Drop for KvmVision {
    fn drop(&mut self) {
        // SAFETY: Deinitializes the libkvm singleton at process shutdown.
        unsafe {
            kvmv_deinit();
        }
    }
}

#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
struct KvmVision {
    _lib: Library,
    read_img: KvmvReadImg,
    free_data: FreeKvmvData,
    set_h264_gop: SetH264Gop,
    set_frame_detect: SetFrameDetect,
    deinit: KvmvDeinit,
    hdmi_control: KvmvHdmiControl,
}

#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
unsafe impl Send for KvmVision {}

#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
impl KvmVision {
    fn load() -> Result<Self> {
        let path = find_libkvm_path()?;
        let lib = Library::open(&path)?;

        // SAFETY: Symbol names and signatures match server/include/kvm_vision.h.
        let init = unsafe { lib.symbol::<KvmvInit>("kvmv_init")? };
        let read_img = unsafe { lib.symbol::<KvmvReadImg>("kvmv_read_img")? };
        let free_data = unsafe { lib.symbol::<FreeKvmvData>("free_kvmv_data")? };
        let set_h264_gop = unsafe { lib.symbol::<SetH264Gop>("set_h264_gop")? };
        let set_frame_detect = unsafe { lib.symbol::<SetFrameDetect>("set_frame_detact")? };
        let deinit = unsafe { lib.symbol::<KvmvDeinit>("kvmv_deinit")? };
        let hdmi_control = unsafe { lib.symbol::<KvmvHdmiControl>("kvmv_hdmi_control")? };

        let vision = Self {
            _lib: lib,
            read_img,
            free_data,
            set_h264_gop,
            set_frame_detect,
            deinit,
            hdmi_control,
        };

        // SAFETY: Initializes libkvm with logging disabled, matching Go backend.
        unsafe {
            init(0);
        }
        vision.initialize_hdmi();

        Ok(vision)
    }

    fn initialize_hdmi(&self) {
        let disabled = Path::new(HDMI_DISABLE_FILE).exists();

        // SAFETY: Mirrors Go backend startup: reset HDMI, wait briefly, then
        // re-enable it unless the persisted disable flag is present.
        unsafe {
            (self.hdmi_control)(0);
        }
        thread::sleep(Duration::from_millis(10));
        if !disabled {
            // SAFETY: Function pointer is loaded from libkvm and accepts 0/1.
            unsafe {
                (self.hdmi_control)(1);
            }
        }
    }

    fn set_frame_detect(&self, frame: u8) {
        // SAFETY: Function pointer is loaded from libkvm.so and accepts a plain u8.
        unsafe {
            (self.set_frame_detect)(frame);
        }
    }

    fn set_h264_gop(&self, gop: u8) {
        // SAFETY: Function pointer is loaded from libkvm.so and accepts a plain u8.
        unsafe {
            (self.set_h264_gop)(gop);
        }
    }

    fn set_hdmi(&self, enabled: bool) -> u8 {
        // SAFETY: Function pointer is loaded from libkvm.so and accepts 0/1.
        unsafe { (self.hdmi_control)(u8::from(enabled)) }
    }

    fn read_img(
        &mut self,
        width: u16,
        height: u16,
        kind: u8,
        quality_or_rate: u16,
    ) -> Result<(Vec<u8>, i32)> {
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut len: u32 = 0;

        // SAFETY: libkvm writes an owned buffer pointer and size on success. The
        // pointer is copied into a Vec and released through free_kvmv_data below.
        let result =
            unsafe { (self.read_img)(width, height, kind, quality_or_rate, &mut ptr, &mut len) };

        if result < 0 {
            return Ok((Vec::new(), result));
        }

        let data = if ptr.is_null() || len == 0 {
            Vec::new()
        } else {
            // SAFETY: ptr/len come from libkvm for this call and remain valid
            // until free_kvmv_data is invoked below.
            unsafe { slice::from_raw_parts(ptr, len as usize).to_vec() }
        };
        // SAFETY: Mirrors the Go backend: release libkvm's output buffer for
        // all non-negative results, including empty/no-change frames.
        unsafe {
            (self.free_data)(&mut ptr);
        }

        Ok((data, result))
    }
}

#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
impl Drop for KvmVision {
    fn drop(&mut self) {
        // SAFETY: Deinitializes the libkvm singleton at process shutdown.
        unsafe {
            (self.deinit)();
        }
    }
}

#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
struct Library {
    handle: *mut c_void,
}

#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
unsafe impl Send for Library {}

#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
impl Library {
    fn open(path: &Path) -> Result<Self> {
        let path = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| AppError::Internal("invalid libkvm path".to_string()))?;
        clear_dlerror();
        // SAFETY: Calls libc dlopen with a NUL-terminated path and RTLD_NOW.
        let handle = unsafe { dlopen(path.as_ptr(), RTLD_NOW) };
        if handle.is_null() {
            return Err(AppError::Internal(format!("load libkvm: {}", dl_error())));
        }
        Ok(Self { handle })
    }

    unsafe fn symbol<T: Copy>(&self, name: &str) -> Result<T> {
        let name = CString::new(name)
            .map_err(|_| AppError::Internal("invalid libkvm symbol name".to_string()))?;
        clear_dlerror();
        // SAFETY: dlsym is called with a valid dlopen handle and symbol name.
        let ptr = unsafe { dlsym(self.handle, name.as_ptr()) };
        if ptr.is_null() {
            return Err(AppError::Internal(format!(
                "load libkvm symbol {}: {}",
                name.to_string_lossy(),
                dl_error()
            )));
        }
        // SAFETY: Caller supplies the expected function pointer type for symbol.
        Ok(unsafe { std::mem::transmute_copy(&ptr) })
    }
}

#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
impl Drop for Library {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: handle was returned by dlopen.
            unsafe {
                dlclose(self.handle);
            }
        }
    }
}

#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
fn find_libkvm_path() -> Result<PathBuf> {
    if let Ok(path) = env::var("NANOKVM_LIBKVM") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
    }

    DEFAULT_LIBKVM_PATHS
        .iter()
        .map(Path::new)
        .find(|path| path.exists())
        .map(Path::to_path_buf)
        .ok_or_else(|| AppError::Internal("libkvm.so not found".to_string()))
}

#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
fn clear_dlerror() {
    // SAFETY: dlerror clears thread-local dynamic loader error state.
    unsafe {
        let _ = dlerror();
    }
}

#[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
fn dl_error() -> String {
    // SAFETY: dlerror returns a C string pointer valid until the next dl call.
    let ptr = unsafe { dlerror() };
    if ptr.is_null() {
        return "unknown dynamic loader error".to_string();
    }
    // SAFETY: ptr is a NUL-terminated C string from dlerror.
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}
