//! Fixed MJPEG recovery publication under broker-owned update/config admission.
use super::{Error, open, protected};
use rand_core::{OsRng, RngCore};
use rustix::fs::{Mode, OFlags, fchmod, openat2, renameat};
use std::{fs::File, io::Write, os::unix::fs::MetadataExt};

pub(crate) fn safe_mode() -> Result<(), Error> {
    if !nix::unistd::geteuid().is_root() || nix::unistd::getegid().as_raw() != 0 {
        return Err(Error::Unsafe);
    }
    safe_mode_at(&File::open("/")?, 0)
}

pub(crate) fn safe_mode_at(root: &File, uid: u32) -> Result<(), Error> {
    protected(root, uid, false)?;
    let app = open(root, "kvmapp", OFlags::RDONLY | OFlags::DIRECTORY, true)?;
    let kvm = open(&app, "kvm", OFlags::RDONLY | OFlags::DIRECTORY, true)?;
    let etc = open(root, "etc", OFlags::RDONLY | OFlags::DIRECTORY, true)?;
    let settings = open(&etc, "kvm", OFlags::RDONLY | OFlags::DIRECTORY, true)?;
    for directory in [&app, &kvm, &etc, &settings] {
        protected(directory, uid, false)?;
    }
    // Check both existing destinations before changing either. No legacy
    // symlink/device/hardlink object is followed or "repaired" by a restart.
    check_member(&kvm, "type", uid)?;
    check_member(&settings, "h264_safe_mode", uid)?;
    publish(&kvm, "type", b"mjpeg\n")?;
    publish(
        &settings,
        "h264_safe_mode",
        b"H.264 encoder health check failed; restarted in MJPEG safe mode\n",
    )
}

fn check_member(parent: &File, name: &str, uid: u32) -> Result<(), Error> {
    match open(parent, name, OFlags::PATH, true) {
        Ok(file) => {
            let m = file.metadata()?;
            if !m.is_file()
                || m.uid() != uid
                || m.nlink() != 1
                || m.dev() != parent.metadata()?.dev()
                || m.mode() & 0o7022 != 0
            {
                return Err(Error::Unsafe);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Error::Unsafe),
    }
    Ok(())
}

fn publish(parent: &File, name: &str, bytes: &[u8]) -> Result<(), Error> {
    let mut nonce = [0; 16];
    OsRng.try_fill_bytes(&mut nonce).map_err(|_| Error::Io)?;
    let temporary = format!(".backend-next-{:032x}", u128::from_le_bytes(nonce));
    let mut file: File = openat2(
        parent,
        temporary.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
        super::RESOLVE | rustix::fs::ResolveFlags::NO_XDEV,
    )
    .map_err(|_| Error::Io)?
    .into();
    fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|_| Error::Io)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    renameat(parent, temporary.as_str(), parent, name).map_err(|_| Error::Io)?;
    parent.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };
    #[test]
    fn fixed_safe_mode_requires_protected_both_destinations_before_first_write() {
        for fault in [
            "valid",
            "parent",
            "symlink",
            "hardlink",
            "mode",
            "directory",
            "fifo",
        ] {
            let root = tempfile::tempdir().unwrap();
            fs::create_dir_all(root.path().join("kvmapp/kvm")).unwrap();
            fs::create_dir_all(root.path().join("etc/kvm")).unwrap();
            let kind = root.path().join("kvmapp/kvm/type");
            fs::write(&kind, b"h264\n").unwrap();
            let marker = root.path().join("etc/kvm/h264_safe_mode");
            fs::write(&marker, b"old marker").unwrap();
            match fault {
                "parent" => {
                    fs::set_permissions(marker.parent().unwrap(), fs::Permissions::from_mode(0o777))
                        .unwrap()
                }
                "symlink" => {
                    fs::remove_file(&marker).unwrap();
                    symlink(&kind, &marker).unwrap();
                }
                "hardlink" => {
                    fs::remove_file(&marker).unwrap();
                    fs::hard_link(&kind, &marker).unwrap();
                }
                "mode" => fs::set_permissions(&marker, fs::Permissions::from_mode(0o666)).unwrap(),
                "directory" => {
                    fs::remove_file(&marker).unwrap();
                    fs::create_dir(&marker).unwrap();
                }
                "fifo" => {
                    fs::remove_file(&marker).unwrap();
                    nix::unistd::mkfifo(&marker, nix::sys::stat::Mode::S_IRUSR).unwrap();
                }
                _ => {}
            }
            let result = safe_mode_at(
                &File::open(root.path()).unwrap(),
                nix::unistd::geteuid().as_raw(),
            );
            assert_eq!(result.is_ok(), fault == "valid", "{fault}");
            assert_eq!(
                fs::read(&kind).unwrap(),
                if fault == "valid" {
                    b"mjpeg\n".as_slice()
                } else {
                    b"h264\n".as_slice()
                }
            );
            if fault == "valid" {
                assert_eq!(kind.metadata().unwrap().mode() & 0o7777, 0o600);
            }
        }
    }
}
