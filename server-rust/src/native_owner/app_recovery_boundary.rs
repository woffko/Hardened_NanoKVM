//! Retained managed-native lifetime boundary for fixed app-slot recovery only.
//! Neither native closure nor a changed boot grants raw/restore or app health.
use super::{Epoch, Error, Phase, Store};

#[must_use = "retain native exclusion until fencing or abandoning recovery"]
pub(crate) struct ReadyAppRecovery {
    store: Store,
    observed: (Epoch, Phase),
}

/// Durable current-boot Stopping plus the native singleton lease. No Group or
/// launch operation is exposed; Drop never publishes Closed or deletes state.
#[must_use = "retain the fence through app recovery and archival durability"]
pub(crate) struct FencedAppRecovery {
    store: Store,
}

impl ReadyAppRecovery {
    pub(crate) fn acquire() -> Result<Self, Error> {
        // Classify missing storage before requiring procfs, without creating
        // native state. Absence never becomes a recovery capability.
        match Store::control_directory() {
            Ok(directory) => drop(directory),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::Absent);
            }
            Err(_) => return Err(Error::Unsafe),
        }
        Self::checked(Store::lock_root(false)?)
    }

    fn checked(store: Store) -> Result<Self, Error> {
        // Strict O_PATH/type/size/identity validation before any record I/O,
        // also rejecting every NEXT/recovery object. The retained singleton
        // excludes all cooperative native journal publishers across both reads.
        Store::check_update_at(&store.directory, store.uid, store.epoch)?;
        let observed = store.read()?.ok_or(Error::Absent)?;
        if observed.0 == store.epoch && observed.1 != Phase::Closed {
            return Err(Error::Unresolved);
        }
        Ok(Self { store, observed })
    }

    pub(crate) fn fence(mut self) -> Result<FencedAppRecovery, Error> {
        Store::check_update_at(&self.store.directory, self.store.uid, self.store.epoch)?;
        if self.store.read()? != Some(self.observed) {
            return Err(Error::Invalid);
        }
        // Before touching the app slot, fence native admission durably. Losing
        // this process must not let an otherwise Ready S95 start new scopes.
        self.store.stopping()?;
        Ok(FencedAppRecovery { store: self.store })
    }
}

impl FencedAppRecovery {
    pub(crate) fn complete(&mut self) -> Result<(), Error> {
        // The lease is still retained after Closed publication. Only the
        // recovery caller may complete this after app durability/archival.
        self.store.close()
    }
}

#[cfg(test)]
pub(crate) fn closed_fixture(parent: &std::fs::File) {
    let mut store = Store::lease(
        parent,
        nix::unistd::geteuid().as_raw(),
        Epoch::current().unwrap(),
        true,
    )
    .unwrap();
    // Explicit empty-managed-group fixture only, never production authority.
    store.begin().unwrap();
    store.close().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_owner::broker::journal::{DIRECTORY, NEXT, RECOVERY, STATE, Step, record};
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
        path::Path,
    };

    const BOOT: &str = "12345678-1234-1234-1234-123456789abc";
    const OTHER: &str = "87654321-4321-4321-4321-cba987654321";

    fn lease(root: &Path, boot: &str, create: bool) -> Result<Store, Error> {
        Store::lease(
            &fs::File::open(root).unwrap(),
            nix::unistd::geteuid().as_raw(),
            Epoch::parse(boot.as_bytes()).unwrap(),
            create,
        )
    }

    fn put(root: &Path, boot: &str, phase: Phase) -> Vec<u8> {
        let bytes = record(Epoch::parse(boot.as_bytes()).unwrap(), phase);
        let path = root.join(DIRECTORY).join(STATE);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        bytes.to_vec()
    }

    #[test]
    fn missing_directory_or_state_is_not_a_native_lifetime_receipt() {
        let root = tempfile::tempdir().unwrap();
        assert!(matches!(
            lease(root.path(), BOOT, false),
            Err(Error::Absent)
        ));
        assert!(!root.path().join(DIRECTORY).exists());
        let store = lease(root.path(), BOOT, true).unwrap();
        assert!(matches!(
            ReadyAppRecovery::checked(store),
            Err(Error::Absent)
        ));
        assert!(!root.path().join(DIRECTORY).join(STATE).exists());
    }

    #[test]
    fn only_closed_same_boot_or_a_different_epoch_allows_readonly_acquisition() {
        for boot in [BOOT, OTHER] {
            for phase in [
                Phase::Active,
                Phase::Closed,
                Phase::Maintenance,
                Phase::Stopping,
            ] {
                let root = tempfile::tempdir().unwrap();
                let store = lease(root.path(), BOOT, true).unwrap();
                let bytes = put(root.path(), boot, phase);
                let path = root.path().join(DIRECTORY).join(STATE);
                let inode = fs::metadata(&path).unwrap().ino();
                let ready = ReadyAppRecovery::checked(store);
                assert_eq!(ready.is_ok(), boot != BOOT || phase == Phase::Closed);
                assert_eq!(fs::read(&path).unwrap(), bytes);
                assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
                if let Ok(ready) = ready {
                    assert!(matches!(lease(root.path(), BOOT, false), Err(Error::Busy)));
                    drop(ready);
                }
                drop(lease(root.path(), BOOT, false).unwrap());
            }
        }
    }

    #[test]
    fn fence_survives_drop_and_completion_retains_the_singleton_until_release() {
        for finish in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let store = lease(root.path(), BOOT, true).unwrap();
            put(root.path(), OTHER, Phase::Active);
            let mut fenced = ReadyAppRecovery::checked(store).unwrap().fence().unwrap();
            assert!(fenced.store.read().unwrap() == Some((fenced.store.epoch, Phase::Stopping)));
            assert!(matches!(lease(root.path(), BOOT, false), Err(Error::Busy)));
            if finish {
                fenced.complete().unwrap();
                assert!(fenced.store.read().unwrap() == Some((fenced.store.epoch, Phase::Closed)));
                assert!(matches!(lease(root.path(), BOOT, false), Err(Error::Busy)));
            }
            drop(fenced);
            let store = lease(root.path(), BOOT, false).unwrap();
            assert_eq!(store.admit().is_ok(), finish);
        }
    }

    #[test]
    fn ambiguous_unsafe_or_changed_state_is_never_repaired_or_adopted() {
        for fault in [
            "next", "recovery", "mode", "hash", "fifo", "symlink", "changed",
        ] {
            let root = tempfile::tempdir().unwrap();
            let store = lease(root.path(), BOOT, true).unwrap();
            put(root.path(), BOOT, Phase::Closed);
            let ready = ReadyAppRecovery::checked(store).unwrap();
            let directory = root.path().join(DIRECTORY);
            let path = directory.join(STATE);
            match fault {
                "next" => symlink(root.path().join("absent"), directory.join(NEXT)).unwrap(),
                "recovery" => fs::create_dir(directory.join(RECOVERY)).unwrap(),
                "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
                "hash" => {
                    fs::write(&path, [0; 80]).unwrap();
                }
                "fifo" | "symlink" => {
                    fs::remove_file(&path).unwrap();
                    if fault == "fifo" {
                        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR).unwrap();
                    } else {
                        symlink(root.path().join("absent"), &path).unwrap();
                    }
                }
                "changed" => {
                    put(root.path(), OTHER, Phase::Closed);
                }
                _ => unreachable!(),
            }
            let before = fs::symlink_metadata(&path).unwrap();
            assert!(ready.fence().is_err(), "{fault}");
            let after = fs::symlink_metadata(&path).unwrap();
            assert_eq!(
                (before.ino(), before.mode(), before.len()),
                (after.ino(), after.mode(), after.len())
            );
            assert_eq!(
                directory.join(NEXT).symlink_metadata().is_ok(),
                fault == "next"
            );
            assert_eq!(directory.join(RECOVERY).exists(), fault == "recovery");
        }
    }

    #[test]
    fn failed_fence_or_completion_retains_evidence_and_never_implicitly_closes() {
        for completing in [false, true] {
            for step in [
                Step::BeforeCreate,
                Step::Created,
                Step::Written,
                Step::FileSynced,
                Step::Renamed,
                Step::DirectorySynced,
            ] {
                let root = tempfile::tempdir().unwrap();
                let store = lease(root.path(), BOOT, true).unwrap();
                let closed = put(root.path(), BOOT, Phase::Closed);
                let mut ready = ReadyAppRecovery::checked(store).unwrap();
                if completing {
                    let mut fenced = ready.fence().unwrap();
                    fenced.store.fail_at = Some(step);
                    assert!(fenced.complete().is_err());
                    assert!(fenced.complete().is_err());
                    assert!(matches!(lease(root.path(), BOOT, false), Err(Error::Busy)));
                    drop(fenced);
                } else {
                    ready.store.fail_at = Some(step);
                    assert!(ready.fence().is_err());
                }
                let bytes = fs::read(root.path().join(DIRECTORY).join(STATE)).unwrap();
                let ambiguous = matches!(step, Step::Created | Step::Written | Step::FileSynced);
                assert_eq!(root.path().join(DIRECTORY).join(NEXT).exists(), ambiguous);
                if !completing && step == Step::BeforeCreate {
                    assert_eq!(bytes, closed); // No fence/capability was returned.
                }
                if (completing && !matches!(step, Step::Renamed | Step::DirectorySynced))
                    || (!completing && !ambiguous && step != Step::BeforeCreate)
                {
                    assert_eq!(bytes[44], Phase::Stopping as u8);
                }
            }
        }
    }

    #[test]
    fn closed_fixture_is_explicit_empty_group_setup_with_real_kernel_epoch() {
        let root = tempfile::tempdir().unwrap();
        closed_fixture(&fs::File::open(root.path()).unwrap());
        let store = Store::lease(
            &fs::File::open(root.path()).unwrap(),
            nix::unistd::geteuid().as_raw(),
            Epoch::current().unwrap(),
            false,
        )
        .unwrap();
        assert!(ReadyAppRecovery::checked(store).is_ok());
    }
}
