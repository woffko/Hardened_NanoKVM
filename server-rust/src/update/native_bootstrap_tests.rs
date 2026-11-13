use super::*;
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf};
use tempfile::{TempDir, tempdir};

const IMAGES: Images<'static> = [
    b"synthetic owner",
    b"synthetic broker",
    b"synthetic client",
    b"synthetic recovery",
];

struct Fixture(TempDir);
impl Fixture {
    fn new() -> Self {
        let root = tempdir().unwrap();
        fs::create_dir(root.path().join("usr")).unwrap();
        fs::create_dir_all(root.path().join("etc/kvm")).unwrap();
        Self(root)
    }
    fn parent(&self) -> io::Result<File> {
        app_bootstrap::parent_at(
            &File::open(self.0.path())?,
            nix::unistd::geteuid().as_raw(),
            true,
        )
    }
    fn path(&self, index: usize) -> PathBuf {
        self.0
            .path()
            .join("usr/libexec")
            .join(restore_binding::NATIVE_RUNTIMES[index].filename())
    }
    fn admission(&self) -> ProcessLock {
        ProcessLock::from_parent(
            &File::open(self.0.path().join("etc/kvm")).unwrap(),
            nix::unistd::geteuid().as_raw(),
        )
        .unwrap()
    }
    fn install(&self, status: app_slot::Status) -> io::Result<()> {
        ensure_at(
            &self.parent()?,
            IMAGES,
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
            status,
            &self.admission(),
        )
    }
    fn member(&self, index: usize, image: &[u8]) {
        self.parent().unwrap();
        fs::write(self.path(index), image).unwrap();
        fs::set_permissions(self.path(index), fs::Permissions::from_mode(0o755)).unwrap();
    }
    fn snapshot(&self) -> BTreeMap<PathBuf, (u64, u32, Vec<u8>)> {
        fs::read_dir(self.path(0).parent().unwrap())
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let metadata = fs::symlink_metadata(&path).unwrap();
                let bytes = if metadata.is_file() {
                    fs::read(&path).unwrap()
                } else {
                    Vec::new()
                };
                (
                    path.file_name().unwrap().into(),
                    (metadata.ino(), metadata.mode(), bytes),
                )
            })
            .collect()
    }
}

#[test]
fn absent_family_is_exact_idempotent_and_never_rewrites_existing_inodes() {
    let fixture = Fixture::new();
    fixture.install(app_slot::Status::NoTransaction).unwrap();
    let before = fixture.snapshot();
    assert_eq!(before.len(), 4);
    for (index, image) in IMAGES.into_iter().enumerate() {
        let metadata = fixture.path(index).metadata().unwrap();
        assert_eq!(fs::read(fixture.path(index)).unwrap(), image);
        assert_eq!(metadata.mode() & 0o7777, 0o755);
        assert_eq!(metadata.nlink(), 1);
    }
    for status in [
        app_slot::Status::NoTransaction,
        app_slot::Status::Transaction(app_slot::Phase::Prepared),
        app_slot::Status::Transaction(app_slot::Phase::Committed),
    ] {
        fixture.install(status).unwrap();
        assert_eq!(fixture.snapshot(), before);
    }
}

#[test]
fn every_missing_role_refuses_creation_under_any_existing_journal() {
    for phase in [
        app_slot::Phase::Prepared,
        app_slot::Phase::Publishing,
        app_slot::Phase::Published,
        app_slot::Phase::Committed,
        app_slot::Phase::RollingBack,
        app_slot::Phase::RolledBack,
    ] {
        for missing in 0..4 {
            let fixture = Fixture::new();
            for (index, image) in IMAGES.into_iter().enumerate() {
                if index != missing {
                    fixture.member(index, image);
                }
            }
            let before = fixture.snapshot();
            assert!(
                fixture
                    .install(app_slot::Status::Transaction(phase))
                    .is_err()
            );
            assert_eq!(fixture.snapshot(), before);
        }
    }
}

#[test]
fn foreign_late_roles_never_authorize_earlier_missing_names_or_repair_files() {
    for (index, image) in IMAGES.into_iter().enumerate() {
        for fault in ["bytes", "mode", "hardlink", "symlink", "fifo"] {
            let fixture = Fixture::new();
            fixture.member(index, image);
            match fault {
                "bytes" => fs::write(fixture.path(index), b"foreign helper bytes").unwrap(),
                "mode" => {
                    fs::set_permissions(fixture.path(index), fs::Permissions::from_mode(0o777))
                        .unwrap()
                }
                "hardlink" => fs::hard_link(
                    fixture.path(index),
                    fixture.path(index).with_extension("alias"),
                )
                .unwrap(),
                "symlink" => {
                    fs::remove_file(fixture.path(index)).unwrap();
                    std::os::unix::fs::symlink("outside", fixture.path(index)).unwrap();
                }
                "fifo" => {
                    fs::remove_file(fixture.path(index)).unwrap();
                    nix::unistd::mkfifo(&fixture.path(index), nix::sys::stat::Mode::S_IRUSR)
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let before = fixture.snapshot();
            assert!(
                fixture.install(app_slot::Status::NoTransaction).is_err(),
                "{index}/{fault}"
            );
            assert_eq!(fixture.snapshot(), before);
        }
    }
}

#[test]
fn an_exact_partial_family_can_resume_only_without_a_transaction() {
    for mask in 0_u8..16 {
        let fixture = Fixture::new();
        for (index, image) in IMAGES.into_iter().enumerate() {
            if mask & (1 << index) != 0 {
                fixture.member(index, image);
            }
        }
        fixture.parent().unwrap();
        let before = fixture.snapshot();
        fixture.install(app_slot::Status::NoTransaction).unwrap();
        let after = fixture.snapshot();
        assert_eq!(after.len(), 4);
        for (path, state) in before {
            assert_eq!(after.get(&path), Some(&state));
        }
    }
}

#[test]
fn wrong_group_or_unsafe_parent_is_not_chmod_or_chown_repaired() {
    let fixture = Fixture::new();
    fixture.install(app_slot::Status::NoTransaction).unwrap();
    let before = fixture.snapshot();
    let parent = fixture.parent().unwrap();
    let gid = nix::unistd::getegid().as_raw();
    assert!(
        ensure_at(
            &parent,
            IMAGES,
            nix::unistd::geteuid().as_raw(),
            gid.wrapping_add(1),
            app_slot::Status::NoTransaction,
            &fixture.admission()
        )
        .is_err()
    );
    assert_eq!(fixture.snapshot(), before);
    fs::set_permissions(
        fixture.path(0).parent().unwrap(),
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    assert!(fixture.install(app_slot::Status::NoTransaction).is_err());
    assert_eq!(fixture.snapshot(), before);
    assert_eq!(
        fixture.path(0).parent().unwrap().metadata().unwrap().mode() & 0o7777,
        0o777
    );
}

#[test]
fn every_special_or_shared_write_parent_mode_refuses_without_repair() {
    for name in ["usr", "usr/libexec"] {
        for mode in [0o1755, 0o2755, 0o4755, 0o775, 0o757] {
            let fixture = Fixture::new();
            fixture.install(app_slot::Status::NoTransaction).unwrap();
            let before = fixture.snapshot();
            let parent = fixture.0.path().join(name);
            fs::set_permissions(&parent, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                fixture.install(app_slot::Status::NoTransaction).is_err(),
                "{name}/{mode:o}"
            );
            assert_eq!(fixture.snapshot(), before);
            assert_eq!(parent.metadata().unwrap().mode() & 0o7777, mode);
        }
    }
}

#[test]
fn missing_build_inputs_are_not_replaced_by_bundled_or_environment_paths() {
    // Host builds deliberately contain empty frames unless an explicit bound
    // fixture build supplied all four. Never authorize synthetic path fallbacks.
    let frames = restore_binding::NATIVE_RUNTIMES.map(embedded::image);
    if frames.iter().any(Result::is_err) {
        assert!(embedded_images().is_err());
    } else {
        let images = embedded_images().unwrap();
        for (index, image) in images.into_iter().enumerate() {
            assert_eq!(image, *frames[index].as_ref().unwrap());
        }
    }
}
