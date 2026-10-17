//! Narrow Linux loop ABI boundary. Only anonymous PUBLIC readonly snapshots
//! enter here; no target partition, named backing path, secret or native code.
#![deny(unsafe_op_in_unsafe_fn)]

use super::{RootfsError, restore_fs};
use linux_raw_sys::{
    ioctl::{BLKGETSIZE64, BLKROGET},
    loop_device::{
        LO_FLAGS_AUTOCLEAR, LO_FLAGS_READ_ONLY, LOOP_CONFIGURE, LOOP_CTL_GET_FREE,
        LOOP_GET_STATUS64, loop_config, loop_info64,
    },
};
use rustix::{
    fs::{OFlags, fcntl_getfl, major, minor},
    io::{FdFlags, fcntl_getfd},
};
use std::{
    fs::File,
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt},
    },
    path::Path,
};

const FLAGS: u32 = LO_FLAGS_READ_ONLY as u32 | LO_FLAGS_AUTOCLEAR as u32;
const MAX_IMAGE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_CLAIM_ATTEMPTS: usize = 8;

// Evaluate on the actual compilation target as well as in host unit tests.
// Supported release ABIs are Linux64 (RV64 target and x86_64 host fixtures).
#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(std::mem::size_of::<loop_info64>() == 232);
    assert!(std::mem::align_of::<loop_info64>() == 8);
    assert!(std::mem::size_of::<loop_config>() == 304);
    assert!(std::mem::align_of::<loop_config>() == 8);
    assert!(std::mem::offset_of!(loop_config, info) == 8);
    assert!(std::mem::offset_of!(loop_config, __reserved) == 240);
};

// These legacy request numbers deliberately do NOT use _IOR/_IOW encoding.
// Use generated architecture-specific UAPI types/constants, not a local ABI.
nix::ioctl_none_bad!(get_free, LOOP_CTL_GET_FREE);
nix::ioctl_write_ptr_bad!(configure, LOOP_CONFIGURE, loop_config);
nix::ioctl_read_bad!(get_status, LOOP_GET_STATUS64, loop_info64);
nix::ioctl_read_bad!(get_readonly, BLKROGET, nix::libc::c_int);
nix::ioctl_read_bad!(get_size, BLKGETSIZE64, u64);

pub(super) struct ReadonlyLoop {
    pub(super) device: File,
    // Keep the exact backing owner alive as long as the loop owner. Never lend
    // either descriptor to a native command; both are CLOEXEC.
    _backing: File,
}

impl ReadonlyLoop {
    pub(super) fn attach(backing: File, size: u64) -> Result<Self, RootfsError> {
        let identity = check_backing(&backing, size)?;
        let devices =
            restore_fs::open_root(Path::new("/dev"), false).map_err(|_| RootfsError::Device)?;
        let control =
            restore_fs::open_beneath(&devices, "loop-control", OFlags::RDWR | OFlags::NONBLOCK)
                .map_err(|_| RootfsError::Device)?;
        check_device(&control, false, 10, 237)?;
        let config = configuration(&backing, size)?;
        for _ in 0..MAX_CLAIM_ATTEMPTS {
            // SAFETY: an owned, validated Linux loop-control character fd is
            // alive. This request has no pointer argument and only allocates a
            // free loop number. A race is handled by atomic LOOP_CONFIGURE.
            let number =
                unsafe { get_free(control.as_raw_fd()) }.map_err(|_| RootfsError::Device)?;
            let number = u32::try_from(number).map_err(|_| RootfsError::Device)?;
            // A bounded decimal kernel result, never an uploaded path.
            let device = restore_fs::open_beneath(
                &devices,
                &format!("loop{number}"),
                OFlags::RDWR | OFlags::NONBLOCK,
            )
            .map_err(|_| RootfsError::Device)?;
            check_device(&device, true, 7, number)?;
            // SAFETY: config is the generated, fully initialized Linux ABI
            // object, valid for this call. Its fd names our live owned readonly
            // regular file. The owned block fd is a checked loop device. Kernel
            // rejection leaves an unclaimed device; EBUSY permits bounded retry.
            match unsafe { configure(device.as_raw_fd(), &config) } {
                Err(nix::errno::Errno::EBUSY) => continue,
                Err(_) => return Err(RootfsError::Device),
                Ok(_) => {}
            }
            // Atomic configure set AUTOCLEAR. From here every error drops this
            // owner: no CLR_FD against a possibly reused device, no global cleanup.
            let claimed = Self {
                device,
                _backing: backing,
            };
            claimed.verify(identity, size, number)?;
            return Ok(claimed);
        }
        Err(RootfsError::Device)
    }

    fn verify(&self, identity: [u64; 2], size: u64, number: u32) -> Result<(), RootfsError> {
        let mut status = empty_status();
        let mut readonly: nix::libc::c_int = 0;
        let mut actual_size = 0_u64;
        // SAFETY: all three output objects have the generated/exact UAPI size,
        // alignment and initialized storage; the owned loop fd remains alive.
        // The kernel may write only those object sizes. Failure aborts the view
        // and closes our AUTOCLEAR owner before any mount/native use.
        unsafe {
            get_status(self.device.as_raw_fd(), &mut status).map_err(|_| RootfsError::Device)?;
            get_readonly(self.device.as_raw_fd(), &mut readonly)
                .map_err(|_| RootfsError::Device)?;
            get_size(self.device.as_raw_fd(), &mut actual_size).map_err(|_| RootfsError::Device)?;
        }
        if !matches_status(&status, identity, size, number) || readonly != 1 || actual_size != size
        {
            return Err(RootfsError::Device);
        }
        Ok(())
    }
}

fn check_backing(file: &File, size: u64) -> Result<[u64; 2], RootfsError> {
    let metadata = file.metadata()?;
    if !(4096..=MAX_IMAGE_BYTES).contains(&size)
        || !size.is_multiple_of(512)
        || !metadata.is_file()
        || metadata.nlink() != 0
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.len() != size
        || metadata.mode() & 0o7022 != 0
        || fcntl_getfl(file).map_err(io::Error::from)? & OFlags::ACCMODE != OFlags::RDONLY
        || !fcntl_getfd(file)
            .map_err(io::Error::from)?
            .contains(FdFlags::CLOEXEC)
    {
        return Err(RootfsError::Image);
    }
    Ok([metadata.dev(), metadata.ino()])
}

fn check_device(
    file: &File,
    block: bool,
    expected_major: u32,
    expected_minor: u32,
) -> Result<(), RootfsError> {
    let metadata = file.metadata()?;
    if (block && !metadata.file_type().is_block_device())
        || (!block && !metadata.file_type().is_char_device())
        || metadata.uid() != 0
        || metadata.mode() & 0o7002 != 0
        || major(metadata.rdev()) != expected_major
        || minor(metadata.rdev()) != expected_minor
        || !fcntl_getfd(file)
            .map_err(io::Error::from)?
            .contains(FdFlags::CLOEXEC)
    {
        return Err(RootfsError::Device);
    }
    Ok(())
}

fn configuration(file: &File, size: u64) -> Result<loop_config, RootfsError> {
    let mut info = empty_status();
    info.lo_sizelimit = size;
    info.lo_flags = FLAGS;
    Ok(loop_config {
        fd: u32::try_from(file.as_raw_fd()).map_err(|_| RootfsError::Image)?,
        block_size: 0,
        info,
        __reserved: [0; 8],
    })
}

fn empty_status() -> loop_info64 {
    loop_info64 {
        lo_device: 0,
        lo_inode: 0,
        lo_rdevice: 0,
        lo_offset: 0,
        lo_sizelimit: 0,
        lo_number: 0,
        lo_encrypt_type: 0,
        lo_encrypt_key_size: 0,
        lo_flags: 0,
        lo_file_name: [0; 64],
        lo_crypt_name: [0; 64],
        lo_encrypt_key: [0; 32],
        lo_init: [0; 2],
    }
}

fn matches_status(status: &loop_info64, identity: [u64; 2], size: u64, number: u32) -> bool {
    status.lo_device == identity[0]
        && status.lo_inode == identity[1]
        && status.lo_rdevice == 0
        && status.lo_offset == 0
        && status.lo_sizelimit == size
        && status.lo_number == number
        && status.lo_flags == FLAGS
        && status.lo_encrypt_type == 0
        && status.lo_encrypt_key_size == 0
        && status.lo_encrypt_key == [0; 32]
        && status.lo_init == [0; 2]
}

#[cfg(test)]
#[path = "restore_rootfs_loop_tests.rs"]
mod tests;
