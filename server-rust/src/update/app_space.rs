//! Advisory private-rootfs admission, not a filesystem allocation reservation.
//! Never spend root-reserved blocks or reclaim history to make a check pass.
use rustix::fs::{StatVfs, StatVfsMountFlags, fstatvfs};
use std::{fs::File, io};

pub(super) const RECOVERY_BYTES: u64 = 16 * 1024 * 1024;
const RECOVERY_INODES: u64 = 128;

#[derive(Clone, Copy)]
pub(super) struct Capacity {
    pub(super) unit: u64,
    bytes: u64,
    inodes: u64,
}

fn valid_unit(unit: u64) -> bool {
    (512..=65536).contains(&unit) && unit.is_power_of_two()
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid app filesystem capacity",
    )
}

impl Capacity {
    #[cfg(test)]
    pub(super) fn fixture(unit: u64, bytes: u64, inodes: u64) -> Self {
        Self {
            unit,
            bytes,
            inodes,
        }
    }

    pub(super) fn read(file: &File) -> io::Result<Self> {
        Self::from_stat(&fstatvfs(file)?)
    }

    fn from_stat(stat: &StatVfs) -> io::Result<Self> {
        if stat.f_flag.contains(StatVfsMountFlags::RDONLY) {
            return Err(rustix::io::Errno::ROFS.into());
        }
        if !valid_unit(stat.f_frsize)
            || stat.f_blocks == 0
            || stat.f_bavail > stat.f_bfree
            || stat.f_bfree > stat.f_blocks
            || stat.f_files == 0
            || stat.f_favail > stat.f_ffree
            || stat.f_ffree > stat.f_files
        {
            return Err(invalid());
        }
        Ok(Self {
            unit: stat.f_frsize,
            // f_bavail, not f_bfree: root's emergency reserve is not update space.
            bytes: stat
                .f_bavail
                .checked_mul(stat.f_frsize)
                .ok_or_else(invalid)?,
            inodes: stat.f_favail,
        })
    }

    pub(super) fn ensure(&self, allocation: u64, inodes: u64) -> io::Result<()> {
        let bytes = allocation.checked_add(RECOVERY_BYTES).ok_or_else(invalid)?;
        let inodes = inodes.checked_add(RECOVERY_INODES).ok_or_else(invalid)?;
        if bytes > self.bytes || inodes > self.inodes {
            return Err(rustix::io::Errno::NOSPC.into());
        }
        Ok(())
    }

    pub(super) fn ensure_growth(&self, before: u64, after: u64) -> io::Result<()> {
        if after < before {
            return Err(invalid());
        }
        let blocks = rounded(after, self.unit)?
            .checked_sub(rounded(before, self.unit)?)
            .ok_or_else(invalid)?;
        self.ensure(blocks, 0)
    }
}

fn rounded(bytes: u64, unit: u64) -> io::Result<u64> {
    bytes
        .checked_add(unit - 1)
        .map(|n| n / unit * unit)
        .ok_or_else(invalid)
}

/// Payload-derived estimate: rounded file data plus a directory block
/// per unique namespace entry and another per directory (including extract).
/// The extra fixed reserve covers journal/metadata work, not unrelated writers.
pub(super) struct Footprint {
    unit: u64,
    allocation: u64,
    inodes: u64,
}

impl Footprint {
    pub(super) fn new(unit: u64) -> io::Result<Self> {
        if !valid_unit(unit) {
            return Err(invalid());
        }
        Ok(Self {
            unit,
            allocation: unit,
            inodes: 1,
        })
    }

    pub(super) fn path(&mut self, regular: bool) -> io::Result<()> {
        let blocks = if regular { 1 } else { 2 };
        self.allocation = self
            .allocation
            .checked_add(blocks * self.unit)
            .ok_or_else(invalid)?;
        self.inodes = self.inodes.checked_add(1).ok_or_else(invalid)?;
        Ok(())
    }

    pub(super) fn file(&mut self, bytes: u64) -> io::Result<()> {
        self.allocation = self
            .allocation
            .checked_add(rounded(bytes, self.unit)?)
            .ok_or_else(invalid)?;
        Ok(())
    }

    pub(super) fn check(&self, capacity: Capacity) -> io::Result<()> {
        if capacity.unit != self.unit {
            return Err(invalid());
        }
        capacity.ensure(self.allocation, self.inodes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_boundary_preserves_bytes_and_inode_reserves() {
        let capacity = Capacity {
            unit: 4096,
            bytes: RECOVERY_BYTES + 8192,
            inodes: RECOVERY_INODES + 2,
        };
        capacity.ensure(8192, 2).unwrap();
        assert_eq!(
            capacity.ensure(8193, 2).unwrap_err().raw_os_error(),
            Some(28)
        );
        assert_eq!(
            capacity.ensure(8192, 3).unwrap_err().raw_os_error(),
            Some(28)
        );
        assert!(capacity.ensure(u64::MAX, 0).is_err());
        assert!(capacity.ensure(0, u64::MAX).is_err());
    }

    #[test]
    fn archive_growth_is_rounded_incrementally_not_double_charged() {
        let capacity = Capacity {
            unit: 4096,
            bytes: RECOVERY_BYTES + 4096,
            inodes: RECOVERY_INODES,
        };
        capacity.ensure_growth(0, 4096).unwrap();
        capacity.ensure_growth(4096, 4097).unwrap();
        capacity.ensure_growth(1, 4096).unwrap();
        assert!(capacity.ensure_growth(0, 4097).is_err());
        assert!(capacity.ensure_growth(5, 1).is_err());
        assert!(capacity.ensure_growth(4097, 0).is_err());
        assert!(capacity.ensure_growth(0, u64::MAX).is_err());
    }

    #[test]
    fn footprint_counts_zero_length_files_directories_and_namespace() {
        let mut footprint = Footprint::new(4096).unwrap();
        footprint.path(false).unwrap();
        footprint.path(true).unwrap();
        footprint.file(0).unwrap();
        assert_eq!((footprint.allocation, footprint.inodes), (4 * 4096, 3));
        footprint.file(4097).unwrap();
        assert_eq!(footprint.allocation, 6 * 4096);
        for unit in [0, 1, 511, 1000, 131072] {
            assert!(Footprint::new(unit).is_err());
        }
        assert!(
            footprint
                .check(Capacity {
                    unit: 8192,
                    bytes: u64::MAX,
                    inodes: u64::MAX
                })
                .is_err()
        );
    }

    #[test]
    fn real_stat_uses_available_not_privileged_free_and_rejects_bad_counters() {
        let root = tempfile::tempdir().unwrap();
        let mut stat = fstatvfs(File::open(root.path()).unwrap()).unwrap();
        stat.f_frsize = 4096;
        stat.f_blocks = 10000;
        stat.f_bfree = 9000;
        stat.f_bavail = 2;
        stat.f_files = 1000;
        stat.f_ffree = 900;
        stat.f_favail = 800;
        let capacity = Capacity::from_stat(&stat).unwrap();
        assert_eq!(capacity.bytes, 8192);
        assert!(capacity.ensure(0, 0).is_err());
        stat.f_bavail = 9001;
        assert!(Capacity::from_stat(&stat).is_err());
        stat.f_bavail = 2;
        stat.f_favail = 901;
        assert!(Capacity::from_stat(&stat).is_err());
        stat.f_favail = 800;
        stat.f_flag |= StatVfsMountFlags::RDONLY;
        assert_eq!(
            Capacity::from_stat(&stat).err().unwrap().raw_os_error(),
            Some(30)
        );
    }
}
