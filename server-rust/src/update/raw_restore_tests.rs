use super::*;
use crate::update::{
    raw_capture::{self, CaptureError, CaptureRequest, TargetImage},
    restore_accounts,
    restore_capsule::ticket::{BootId, Phase, RestoreTicket, Store},
    restore_identity::{
        IdentityCheckedRestore,
        tests::{CONFIG_PATH, CWD, fixture, signed_accounts},
    },
};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, sync::atomic::AtomicBool};
use tempfile::TempDir;

const VERSION: &str = "0.3.0-raw.13";
const APP: &str = "2.0.43";
const TARGET: &str = "sg2002-licheervnano-sd";
const SOURCE: &str = "11111111-1111-4111-8111-111111111111";
const BOOT: &str = "22222222-2222-4222-8222-222222222222";

struct Image;
impl TargetImage for Image {
    fn signed_accounts(
        &mut self,
        _: &AtomicBool,
    ) -> std::result::Result<restore_accounts::SignedAccounts, CaptureError> {
        let encoded = restore_accounts::encode(
            &signed_accounts(),
            &restore_accounts::ImageFacts {
                app_version: APP.into(),
                restorable: true,
            },
        )
        .unwrap();
        Ok(restore_accounts::decode(&encoded).unwrap())
    }
    fn check_ssh(
        &mut self,
        _: &mut IdentityCheckedRestore,
        _: &AtomicBool,
    ) -> std::result::Result<(), CaptureError> {
        Ok(())
    }
}

fn private() -> TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn capture_ticket(source: &Path, config: &crate::config::Config, capsules: &Path) -> RestoreTicket {
    capture_ticket_for(VERSION, source, config, capsules)
}

fn capture_ticket_for(
    version: &str,
    source: &Path,
    config: &crate::config::Config,
    capsules: &Path,
) -> RestoreTicket {
    let staging = private();
    let capsule_directory = fs::File::open(capsules).unwrap();
    let request = CaptureRequest {
        source_root: source,
        private_staging: staging.path(),
        capsule_directory: &capsule_directory,
        config,
        working_dir: Path::new(CWD),
        config_path: Path::new(CONFIG_PATH),
        target_version: version,
        target: TARGET,
        boot_image_sha256: [2; 32],
        rootfs_image_sha256: [3; 32],
        source_boot: BootId::parse(SOURCE).unwrap(),
        device_id: [1; 32],
    };
    raw_capture::capture(&request, &mut Image, &AtomicBool::new(false))
        .unwrap()
        .into_ticket()
}

fn restored_root(source: &Path, required: bool) -> TempDir {
    let root = private();
    for path in [
        "etc",
        "etc/kvm",
        "etc/kvm/network",
        "etc/kvm/cache",
        "etc/ssh",
        "etc/dropbear",
        "root",
        "root/.ssh",
        "root/.picoclaw",
        "var",
        "var/lib",
        "var/lib/tailscale",
        "kvmapp",
        "kvmapp/kvm",
        "mnt",
        "mnt/data",
        "boot",
    ] {
        fs::create_dir_all(root.path().join(path)).unwrap();
    }
    for name in ["passwd", "group", "shadow", "gshadow"] {
        let source = source.join("etc").join(name);
        if source.exists() {
            fs::copy(&source, root.path().join("etc").join(name)).unwrap();
        }
    }
    fs::write(
        root.path().join("etc/kvm/system-version.json"),
        format!(r#"{{"version":"{VERSION}","target":"{TARGET}"}}"#),
    )
    .unwrap();
    fs::write(root.path().join("kvmapp/version"), format!("{APP}\n")).unwrap();
    if required {
        let marker = root.path().join(REQUIRED_PATH);
        fs::write(&marker, REQUIRED_BYTES).unwrap();
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o644)).unwrap();
    }
    root
}

fn observation() -> Observation {
    Observation {
        boot_id: BootId::parse(BOOT).unwrap(),
        device_id: [1; 32],
        system_version: VERSION.into(),
        app_version: APP.into(),
        target: TARGET.into(),
    }
}

#[test]
fn required_raw_image_applies_once_and_commits_the_ticket() {
    let (source, config) = fixture();
    let capsules = private();
    let store_root = private();
    let staging = private();
    let marker_dir = tempfile::tempdir().unwrap();
    let marker = marker_dir.path().join("blocked");
    let root = restored_root(source.path(), true);
    let ticket = capture_ticket(source.path(), &config, capsules.path());
    let mut store = Store::open_fixture(store_root.path()).unwrap();
    store.publish_prepared(&ticket).unwrap();
    let outcome = run_observed(
        root.path(),
        &mut store,
        capsules.path(),
        staging.path(),
        &marker,
        &observation(),
    )
    .unwrap();
    assert_eq!(outcome, Outcome::Applied);
    assert_eq!(store.load().unwrap().unwrap().phase(), Phase::Committed);
    assert!(!marker.exists());
    assert_eq!(fs::read_dir(capsules.path()).unwrap().count(), 0);
    assert!(root.path().join("etc/kvm/server.yaml").exists());
    assert!(!root.path().join(REQUIRED_PATH).exists());
    let second = run_observed(
        root.path(),
        &mut store,
        capsules.path(),
        staging.path(),
        &marker,
        &observation(),
    )
    .unwrap();
    assert_eq!(second, Outcome::NotRequired);
}

fn applied(source: &Path, config: &crate::config::Config) -> TempDir {
    let capsules = private();
    let store_root = private();
    let staging = private();
    let marker_dir = tempfile::tempdir().unwrap();
    let root = restored_root(source, true);
    fs::write(
        root.path().join("etc/kvm/server.yaml"),
        include_bytes!(
            "../../../buildroot-external/hardened-sg2002/board/sg2002/overlay/etc/kvm/server.yaml"
        ),
    )
    .unwrap();
    let ticket = capture_ticket(source, config, capsules.path());
    let mut store = Store::open_fixture(store_root.path()).unwrap();
    store.publish_prepared(&ticket).unwrap();
    let outcome = run_observed(
        root.path(),
        &mut store,
        capsules.path(),
        staging.path(),
        &marker_dir.path().join("blocked"),
        &observation(),
    )
    .unwrap();
    assert_eq!(outcome, Outcome::Applied);
    root
}

#[test]
fn the_https_of_a_new_installation_never_reaches_a_device_on_http() {
    let proto = |root: &TempDir| {
        let yaml = fs::read(root.path().join("etc/kvm/server.yaml")).unwrap();
        serde_yaml::from_slice::<crate::config::Config>(&yaml)
            .unwrap()
            .proto
    };
    let (source, config) = fixture();
    assert_eq!(proto(&applied(source.path(), &config)), "http");
    fs::remove_file(source.path().join("etc/kvm/server.yaml")).unwrap();
    fs::write(
        source.path().join("etc/kvm/session_secret"),
        format!("{}\n", config.jwt.secret_key),
    )
    .unwrap();
    assert_eq!(proto(&applied(source.path(), &config)), "http");
}

#[test]
fn the_mldsa_key_pair_survives_capture_archive_and_apply() {
    let (source, config) = fixture();
    let files: [(&str, &[u8], u32); 4] = [
        (
            "etc/ssh/ssh_host_mldsa44_ed25519_key",
            b"synthetic private key",
            0o600,
        ),
        (
            "etc/ssh/ssh_host_mldsa44_ed25519_key.pub",
            b"synthetic public key",
            0o644,
        ),
        (
            "etc/ssh/ssh_host_mldsa44_ed25519_key-cert.pub",
            b"synthetic certificate",
            0o644,
        ),
        ("etc/ssh/ssh_config", b"# synthetic client config\n", 0o644),
    ];
    for (path, bytes, _) in files {
        fs::write(source.path().join(path), bytes).unwrap();
    }
    let root = applied(source.path(), &config);
    for (path, bytes, mode) in files {
        let target = root.path().join(path);
        assert_eq!(fs::read(&target).unwrap(), bytes, "{path}");
        let found = fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
        assert_eq!(found, mode, "{path}");
    }
}

struct Restored {
    root: TempDir,
    capsules: TempDir,
    staging: TempDir,
    marker: TempDir,
    store: Store,
    _store_root: TempDir,
}

impl Restored {
    fn new() -> (Self, TempDir, crate::config::Config) {
        let (source, config) = fixture();
        let capsules = private();
        let store_root = private();
        let staging = private();
        let marker = tempfile::tempdir().unwrap();
        let root = restored_root(source.path(), true);
        let ticket = capture_ticket(source.path(), &config, capsules.path());
        let mut store = Store::open_fixture(store_root.path()).unwrap();
        store.publish_prepared(&ticket).unwrap();
        let mut restored = Self {
            root,
            capsules,
            staging,
            marker,
            store,
            _store_root: store_root,
        };
        assert_eq!(restored.boot().unwrap(), Outcome::Applied);
        (restored, source, config)
    }

    fn boot(&mut self) -> Result<Outcome> {
        run_observed(
            self.root.path(),
            &mut self.store,
            self.capsules.path(),
            self.staging.path(),
            &self.marker.path().join("blocked"),
            &observation(),
        )
    }

    fn blocked(&self) -> bool {
        self.marker.path().join("blocked").exists()
    }
}

#[test]
fn a_restored_system_boots_whatever_later_happens_to_the_boot_ticket() {
    let (mut restored, source, config) = Restored::new();
    let next = capture_ticket_for(
        "0.4.0-raw.1",
        source.path(),
        &config,
        restored.capsules.path(),
    );
    restored.store.publish_prepared(&next).unwrap();
    assert_eq!(restored.boot().unwrap(), Outcome::NotRequired);
    assert!(!restored.blocked());
    let current = restored.store.load().unwrap().unwrap();
    restored.store.abandon_prepared(&current).unwrap();
    assert_eq!(restored.boot().unwrap(), Outcome::NotRequired);
    assert!(!restored.blocked());
}

#[test]
fn a_boot_interrupted_after_the_commit_finishes_on_the_next_boot() {
    let (mut restored, _source, _config) = Restored::new();
    let requirement = restored.root.path().join(REQUIRED_PATH);
    fs::write(&requirement, REQUIRED_BYTES).unwrap();
    fs::set_permissions(&requirement, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(restored.boot().unwrap(), Outcome::AlreadyCommitted);
    assert!(!requirement.exists());
    assert!(!restored.blocked());
}

#[test]
fn a_fresh_image_does_not_inherit_the_receipt_of_an_earlier_system() {
    let (mut restored, _source, _config) = Restored::new();
    let requirement = restored.root.path().join(REQUIRED_PATH);
    fs::write(&requirement, REQUIRED_BYTES).unwrap();
    fs::set_permissions(&requirement, fs::Permissions::from_mode(0o644)).unwrap();
    let mut newer = observation();
    newer.system_version = "0.4.0-raw.1".into();
    let result = run_observed(
        restored.root.path(),
        &mut restored.store,
        restored.capsules.path(),
        restored.staging.path(),
        &restored.marker.path().join("blocked"),
        &newer,
    );
    assert!(matches!(
        result,
        Err(Error::Ticket(ticket::TicketError::WrongBoot))
    ));
    assert!(restored.blocked());
    assert!(requirement.exists());
}

#[test]
fn a_cleanup_failure_after_the_commit_does_not_block_management() {
    let (source, config) = fixture();
    let capsules = private();
    let store_root = private();
    let staging = private();
    let marker_dir = tempfile::tempdir().unwrap();
    let marker = marker_dir.path().join("blocked");
    let root = restored_root(source.path(), true);
    let ticket = capture_ticket(source.path(), &config, capsules.path());
    let mut store = Store::open_fixture(store_root.path()).unwrap();
    store.publish_prepared(&ticket).unwrap();
    assert_eq!(
        run_observed(
            root.path(),
            &mut store,
            capsules.path(),
            staging.path(),
            &marker,
            &observation(),
        )
        .unwrap(),
        Outcome::Applied
    );
    // The capsule directory is gone now, as on a damaged data partition.
    let requirement = root.path().join(REQUIRED_PATH);
    fs::write(&requirement, REQUIRED_BYTES).unwrap();
    fs::set_permissions(&requirement, fs::Permissions::from_mode(0o644)).unwrap();
    let file_not_directory = capsules.path().join("not-a-directory");
    fs::write(&file_not_directory, b"x").unwrap();
    assert_eq!(
        run_observed(
            root.path(),
            &mut store,
            &file_not_directory,
            staging.path(),
            &marker,
            &observation(),
        )
        .unwrap(),
        Outcome::AlreadyCommitted
    );
    assert!(!marker.exists());
}

#[test]
fn a_temporary_file_left_by_a_power_cut_does_not_block_the_restore() {
    let (source, config) = fixture();
    let capsules = private();
    let store_root = private();
    let staging = private();
    let marker_dir = tempfile::tempdir().unwrap();
    let marker = marker_dir.path().join("blocked");
    let root = restored_root(source.path(), true);
    for index in 0..256 {
        let name = format!(".nanokvm-restore-{}-{index}", std::process::id());
        fs::write(root.path().join("etc/kvm").join(&name), b"partial").unwrap();
    }
    let ticket = capture_ticket(source.path(), &config, capsules.path());
    let mut store = Store::open_fixture(store_root.path()).unwrap();
    store.publish_prepared(&ticket).unwrap();
    assert_eq!(
        run_observed(
            root.path(),
            &mut store,
            capsules.path(),
            staging.path(),
            &marker,
            &observation(),
        )
        .unwrap(),
        Outcome::Applied
    );
    assert!(!marker.exists());
}

#[test]
fn factory_image_without_the_marker_is_not_restored() {
    let (source, config) = fixture();
    let capsules = private();
    let store_root = private();
    let staging = private();
    let marker_dir = tempfile::tempdir().unwrap();
    let marker = marker_dir.path().join("blocked");
    let root = restored_root(source.path(), false);
    let ticket = capture_ticket(source.path(), &config, capsules.path());
    let mut store = Store::open_fixture(store_root.path()).unwrap();
    store.publish_prepared(&ticket).unwrap();
    let outcome = run_observed(
        root.path(),
        &mut store,
        capsules.path(),
        staging.path(),
        &marker,
        &observation(),
    )
    .unwrap();
    assert_eq!(outcome, Outcome::NotRequired);
    assert!(!marker.exists());
    assert_eq!(store.load().unwrap().unwrap().phase(), Phase::Prepared);
}

#[test]
fn fresh_image_restores_optional_and_nested_parents_before_committing() {
    let (source, config) = fixture();
    let paths = [
        "etc/kvm/cache/wol",
        "etc/kvm/network/dns.mode",
        "etc/kvm/scripts/task.sh",
        "root/.picoclaw/workspace/notes/nested/item.txt",
    ];
    for path in paths {
        let target = source.path().join(path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, b"saved setting\n").unwrap();
    }
    let root = restored_root(source.path(), true);
    for parent in ["etc/kvm/cache", "etc/kvm/network", "root/.picoclaw"] {
        fs::remove_dir(root.path().join(parent)).unwrap();
    }
    let capsules = private();
    let store_root = private();
    let staging = private();
    let marker = root.path().join("blocked");
    let ticket = capture_ticket(source.path(), &config, capsules.path());
    let mut store = Store::open_fixture(store_root.path()).unwrap();
    store.publish_prepared(&ticket).unwrap();
    assert_eq!(
        run_observed(
            root.path(),
            &mut store,
            capsules.path(),
            staging.path(),
            &marker,
            &observation()
        )
        .unwrap(),
        Outcome::Applied
    );
    for path in paths {
        let target = root.path().join(path);
        assert_eq!(fs::read(&target).unwrap(), b"saved setting\n");
        assert_eq!(
            fs::metadata(target.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    assert_eq!(store.load().unwrap().unwrap().phase(), Phase::Committed);
}

#[test]
fn target_parents_reject_symlinks_and_absence_does_not_create_directories() {
    let root = private();
    let outside = private();
    fs::create_dir_all(root.path().join("etc/kvm")).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("etc/kvm/cache")).unwrap();
    assert!(parent_directory(root.path(), "etc/kvm/cache/wol", true).is_err());
    assert!(remove_member(root.path(), "etc/kvm/cache/wol").is_err());
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    assert!(
        parent_directory(root.path(), "root/.ssh/config", false)
            .unwrap()
            .is_none()
    );
    assert!(!root.path().join("root").exists());
    for path in ["../outside", "/etc/passwd", "etc/../passwd", ""] {
        assert!(parent_directory(root.path(), path, true).is_err());
    }
}

#[test]
fn raw_image_without_a_ticket_fails_closed_and_writes_the_block_marker() {
    let (source, _config) = fixture();
    let capsules = private();
    let store_root = private();
    let staging = private();
    let marker_dir = tempfile::tempdir().unwrap();
    let marker = marker_dir.path().join("blocked");
    let root = restored_root(source.path(), true);
    let mut store = Store::open_fixture(store_root.path()).unwrap();
    assert!(matches!(
        run_observed(
            root.path(),
            &mut store,
            capsules.path(),
            staging.path(),
            &marker,
            &observation(),
        ),
        Err(Error::MissingTicket)
    ));
    assert!(marker.exists());
}

#[test]
fn a_marker_with_wrong_bytes_or_permissions_fails_closed() {
    let (source, _config) = fixture();
    let capsules = private();
    let store_root = private();
    let staging = private();
    let marker_dir = tempfile::tempdir().unwrap();
    let marker = marker_dir.path().join("blocked");
    let root = restored_root(source.path(), true);
    let discriminator = root.path().join(REQUIRED_PATH);
    fs::write(&discriminator, b"wrong\n").unwrap();
    fs::set_permissions(&discriminator, fs::Permissions::from_mode(0o644)).unwrap();
    let mut store = Store::open_fixture(store_root.path()).unwrap();
    assert!(matches!(
        run_observed(
            root.path(),
            &mut store,
            capsules.path(),
            staging.path(),
            &marker,
            &observation(),
        ),
        Err(Error::InvalidMarker)
    ));
    assert!(marker.exists());
}
