use super::*;
use std::{
    io::Write,
    mem::{align_of, offset_of, size_of},
    os::unix::fs::PermissionsExt,
};

fn readonly_image() -> File {
    let mut writable = tempfile::tempfile().unwrap();
    writable.write_all(&[0x5a; 8192]).unwrap();
    let file = File::open(format!("/proc/self/fd/{}", writable.as_raw_fd())).unwrap();
    drop(writable);
    file
}

#[test]
fn generated_loop_abi_has_exact_layout_and_atomic_readonly_no_partscan_request() {
    assert_eq!(
        (size_of::<loop_info64>(), align_of::<loop_info64>()),
        (232, 8)
    );
    assert_eq!(
        (size_of::<loop_config>(), align_of::<loop_config>()),
        (304, 8)
    );
    assert_eq!(offset_of!(loop_config, info), 8);
    assert_eq!(offset_of!(loop_config, __reserved), 240);
    assert_eq!(offset_of!(loop_info64, lo_flags), 52);
    assert_eq!(LOOP_CONFIGURE, 0x4c0a);
    assert_eq!(LOOP_GET_STATUS64, 0x4c05);
    assert_eq!(LOOP_CTL_GET_FREE, 0x4c82);
    let file = readonly_image();
    let config = configuration(&file, 8192).unwrap();
    assert_eq!(config.fd, file.as_raw_fd() as u32);
    assert_eq!(config.block_size, 0);
    assert_eq!(config.info.lo_offset, 0);
    assert_eq!(config.info.lo_sizelimit, 8192);
    assert_eq!(config.info.lo_flags, 5);
    assert_eq!(config.info.lo_file_name, [0; 64]);
    assert_eq!(config.info.lo_crypt_name, [0; 64]);
    assert_eq!(config.__reserved, [0; 8]);
}

#[test]
fn backing_guards_reject_named_writable_wrong_size_unaligned_unsafe_mode_or_nonregular() {
    let file = readonly_image();
    assert!(check_backing(&file, 8192).is_ok());
    for size in [0, 4095, 8191, 8193, MAX_IMAGE_BYTES + 512] {
        assert!(matches!(
            check_backing(&file, size),
            Err(RootfsError::Image)
        ));
    }
    let named = tempfile::NamedTempFile::new().unwrap();
    named.as_file().set_len(8192).unwrap();
    let named_readonly = File::open(named.path()).unwrap();
    assert!(matches!(
        check_backing(&named_readonly, 8192),
        Err(RootfsError::Image)
    ));
    let writable = tempfile::tempfile().unwrap();
    writable.set_len(8192).unwrap();
    assert!(matches!(
        check_backing(&writable, 8192),
        Err(RootfsError::Image)
    ));
    for mode in [0o622, 0o660, 0o4600] {
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .unwrap();
        assert!(matches!(
            check_backing(&file, 8192),
            Err(RootfsError::Image)
        ));
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    rustix::io::fcntl_setfd(&file, FdFlags::empty()).unwrap();
    assert!(matches!(
        check_backing(&file, 8192),
        Err(RootfsError::Image)
    ));
    rustix::io::fcntl_setfd(&file, FdFlags::CLOEXEC).unwrap();
    for path in ["/dev/null", "/"] {
        assert!(matches!(
            check_backing(&File::open(path).unwrap(), 8192),
            Err(RootfsError::Image)
        ));
    }
}

#[test]
fn kernel_status_must_bind_every_security_relevant_loop_property() {
    let mut status = empty_status();
    status.lo_device = 12;
    status.lo_inode = 34;
    status.lo_sizelimit = 8192;
    status.lo_number = 7;
    status.lo_flags = FLAGS;
    assert!(matches_status(&status, [12, 34], 8192, 7));
    for change in 0..11 {
        let mut altered = status;
        match change {
            0 => altered.lo_device += 1,
            1 => altered.lo_inode += 1,
            2 => altered.lo_rdevice = 1,
            3 => altered.lo_sizelimit -= 512,
            4 => altered.lo_offset = 512,
            5 => altered.lo_number += 1,
            6 => altered.lo_flags ^= LO_FLAGS_READ_ONLY as u32,
            7 => altered.lo_flags ^= LO_FLAGS_AUTOCLEAR as u32,
            8 => altered.lo_flags |= linux_raw_sys::loop_device::LO_FLAGS_PARTSCAN as u32,
            9 => altered.lo_encrypt_type = 1,
            10 => altered.lo_encrypt_key_size = 1,
            _ => unreachable!(),
        }
        assert!(
            !matches_status(&altered, [12, 34], 8192, 7),
            "mutation {change}"
        );
    }
    status.lo_encrypt_key[0] = 1;
    assert!(!matches_status(&status, [12, 34], 8192, 7));
    status.lo_encrypt_key[0] = 0;
    status.lo_init[0] = 1;
    assert!(!matches_status(&status, [12, 34], 8192, 7));
}

#[test]
fn real_kernel_rejects_loop_requests_on_regular_files_without_modification() {
    let file = readonly_image();
    let config = configuration(&file, 8192).unwrap();
    let mut status = empty_status();
    let mut readonly = 0;
    let mut size = 0;
    // SAFETY: all fds are live regular files, and pointer arguments are exact
    // generated/initialized ABI objects. A regular file rejects these loop and
    // block requests with ENOTTY; no device is opened/configured by this test.
    unsafe {
        assert_eq!(get_free(file.as_raw_fd()), Err(nix::errno::Errno::ENOTTY));
        assert_eq!(
            configure(file.as_raw_fd(), &config),
            Err(nix::errno::Errno::ENOTTY)
        );
        assert_eq!(
            get_status(file.as_raw_fd(), &mut status),
            Err(nix::errno::Errno::ENOTTY)
        );
        assert_eq!(
            get_readonly(file.as_raw_fd(), &mut readonly),
            Err(nix::errno::Errno::ENOTTY)
        );
        assert_eq!(
            get_size(file.as_raw_fd(), &mut size),
            Err(nix::errno::Errno::ENOTTY)
        );
    }
    assert_eq!(file.metadata().unwrap().len(), 8192);
    assert!(matches!(
        check_device(&file, true, 7, 0),
        Err(RootfsError::Device)
    ));
    assert!(matches!(
        check_device(&file, false, 10, 237),
        Err(RootfsError::Device)
    ));
}
