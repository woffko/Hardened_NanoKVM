use super::*;
use sha2::{Digest, Sha512};
use std::process::Command;
use tempfile::{TempDir, tempdir};

struct SigningFixture {
    directory: TempDir,
    private: PathBuf,
    public: PathBuf,
    config: Config,
}

impl SigningFixture {
    fn new() -> Self {
        let directory = tempdir().unwrap();
        let private = directory.path().join("synthetic-only.pem");
        let public = directory.path().join("synthetic-only.pub.pem");
        let output = Command::new("/usr/bin/openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
            ])
            .arg(&private)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "synthetic fixture key generation failed"
        );
        let output = Command::new("/usr/bin/openssl")
            .args(["pkey", "-in"])
            .arg(&private)
            .args(["-pubout", "-out"])
            .arg(&public)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "synthetic public fixture extraction failed"
        );
        fs::set_permissions(&public, fs::Permissions::from_mode(0o644)).unwrap();
        let mut config = Config::default();
        config.paths.system_update_public_key = public.clone();
        Self {
            directory,
            private,
            public,
            config,
        }
    }

    fn sign(&self, metadata: &[u8]) -> Vec<u8> {
        let source = self.directory.path().join("synthetic-metadata.json");
        let signature = self.directory.path().join("synthetic-metadata.sig");
        fs::write(&source, metadata).unwrap();
        let output = Command::new("/usr/bin/openssl")
            .args(["dgst", "-sha256", "-sign"])
            .arg(&self.private)
            .arg("-out")
            .arg(&signature)
            .arg(&source)
            .output()
            .unwrap();
        assert!(output.status.success(), "synthetic signing failed");
        fs::read(signature).unwrap()
    }

    fn policy(&self, allowed: &str) {
        let path = self.directory.path().join("update-key-policy");
        fs::write(&path, allowed).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
    }
}

fn latest_for(bytes: &[u8]) -> LatestRelease {
    LatestRelease {
        version: "2.0.43".into(),
        name: "hardened-nanokvm-kvmapp-2.0.43.tar.gz".into(),
        sha512: STANDARD.encode(Sha512::digest(bytes)),
        size: bytes.len() as u64,
        url: "https://github.com/woffko/Hardened_NanoKVM/releases/download/synthetic/hardened-nanokvm-kvmapp-2.0.43.tar.gz".into(),
        signature_algorithm: APP_UPDATE_SIGNATURE_ALGORITHM.into(),
        signature_key_id: "hardened-system-dev".into(),
    }
}

#[tokio::test]
async fn exact_app_receipt_rejects_reserialization_forgery_and_invalid_budgets() {
    let fixture = SigningFixture::new();
    let latest = latest_for(b"synthetic public archive");
    let mut bytes = serde_json::to_vec_pretty(&latest).unwrap();
    bytes.push(b'\n');
    let signature = fixture.sign(&bytes);
    let verified = authenticate_app_metadata(bytes.clone(), signature.clone(), &fixture.config)
        .await
        .unwrap();
    assert_eq!(verified.metadata, bytes);
    assert_eq!(verified.signature, signature);
    assert_eq!(verified.latest.sha512, latest.sha512);
    let mut modified = bytes.clone();
    modified.push(b'\n');
    assert!(
        authenticate_app_metadata(modified, signature.clone(), &fixture.config)
            .await
            .is_err()
    );
    let mut forged = latest.clone();
    forged.sha512 = STANDARD.encode([0; 64]);
    assert!(
        authenticate_app_metadata(
            serde_json::to_vec(&forged).unwrap(),
            signature.clone(),
            &fixture.config
        )
        .await
        .is_err()
    );
    for bad in [Vec::new(), vec![0; 256], vec![0; MAX_SIGNATURE + 1]] {
        assert!(
            authenticate_app_metadata(bytes.clone(), bad, &fixture.config)
                .await
                .is_err()
        );
    }
    for bad in [
        Vec::new(),
        vec![b' '; MAX_METADATA + 1],
        b"{\"version\":\"wrong\"}".to_vec(),
    ] {
        assert!(
            authenticate_app_metadata(bad, signature.clone(), &fixture.config)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn app_install_rechecks_revoked_key_policy_and_replaced_public_key() {
    let fixture = SigningFixture::new();
    fixture.policy("hardened-system-dev\n");
    let bytes = serde_json::to_vec(&latest_for(b"archive")).unwrap();
    let signature = fixture.sign(&bytes);
    let mut fetched = authenticate_app_metadata(bytes.clone(), signature.clone(), &fixture.config)
        .await
        .unwrap();
    // A cached parsed view is not reauthentication authority.
    fetched.latest.sha512 = STANDARD.encode([0; 64]);
    let reparsed = authenticate_app_metadata(fetched.metadata, fetched.signature, &fixture.config)
        .await
        .unwrap();
    assert_eq!(reparsed.latest.sha512, latest_for(b"archive").sha512);
    fixture.policy("hardened-system-prod-2026q3\n");
    assert!(
        authenticate_app_metadata(reparsed.metadata, reparsed.signature, &fixture.config)
            .await
            .is_err()
    );
    fixture.policy("hardened-system-dev\n");
    let other = SigningFixture::new();
    fs::copy(&other.public, &fixture.public).unwrap();
    assert!(
        authenticate_app_metadata(bytes, signature, &fixture.config)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn online_unsigned_lab_permission_is_rechecked_and_is_not_manual_import() {
    use crate::update::state_writers::StateWriters;
    let mut latest = latest_for(b"archive");
    latest.signature_algorithm = APP_UPDATE_UNSIGNED_ALGORITHM.into();
    latest.signature_key_id = APP_UPDATE_UNSIGNED_ALGORITHM.into();
    let bytes = serde_json::to_vec(&latest).unwrap();
    let mut old_config = Config::default();
    assert!(
        authenticate_app_metadata(bytes.clone(), Vec::new(), &old_config)
            .await
            .is_err()
    );
    old_config.security.allow_unsigned_updates = true;
    let stored = tempdir().unwrap();
    let writers = StateWriters::for_test_config(
        fs::File::open(stored.path()).unwrap(),
        stored.path().join("server.yaml"),
    );
    let permit = writers.configuration().unwrap();
    old_config.write(&permit).unwrap();
    let fetched_config = Config::read_for(&permit).unwrap();
    let fetched = authenticate_app_metadata(bytes.clone(), Vec::new(), &fetched_config)
        .await
        .unwrap();
    let current_config = Config::default();
    current_config.write(&permit).unwrap();
    let current_config = Config::read_for(&permit).unwrap();
    assert!(
        authenticate_app_metadata(fetched.metadata, fetched.signature, &current_config)
            .await
            .is_err()
    );
    assert!(
        authenticate_app_metadata(bytes, b"not an unsigned receipt".to_vec(), &old_config)
            .await
            .is_err()
    );
    assert!(old_config.security.allow_unsigned_updates);
}

fn package(version: &[u8]) -> Vec<u8> {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut builder = tar::Builder::new(encoder);
    for (path, bytes) in [
        ("kvmapp/version", version),
        (
            "kvmapp/server/NanoKVM-Server",
            b"synthetic non-executable backend".as_slice(),
        ),
        (
            "kvmapp/system/init.d/S95nanokvm",
            b"synthetic init".as_slice(),
        ),
        (
            "kvmapp/backends/NanoKVM-Server.rust",
            b"synthetic backend".as_slice(),
        ),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder.append_data(&mut header, path, bytes).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

#[tokio::test]
async fn online_candidate_version_is_bound_to_verified_metadata_before_live_mutation() {
    let fixture = SigningFixture::new();
    for version in [b"2.0.43\n".as_slice(), b"2.0.42\n"] {
        let bytes = package(version);
        let metadata = serde_json::to_vec(&latest_for(&bytes)).unwrap();
        let signature = fixture.sign(&metadata);
        let verified = authenticate_app_metadata(metadata, signature, &fixture.config)
            .await
            .unwrap();
        let root = tempdir().unwrap();
        let stage = AppStage::fixture(root.path()).unwrap();
        let mut download = stage.create_archive().unwrap();
        download.append(&bytes).unwrap();
        let source = download
            .finish_online(
                verified.latest.size,
                &decode_sha512(&verified.latest.sha512).unwrap(),
            )
            .unwrap();
        let result =
            prepare_app_candidate(source, &stage, &InstallAuthority::OnlineMetadata(verified));
        assert_eq!(result.is_ok(), version == b"2.0.43\n");
        if let Err(error) = result {
            assert!(error.to_string().contains("version differs"));
        }
    }
    // Administrative import does not invent online metadata/signature authority.
    let bytes = package(b"2.0.42\n");
    let root = tempdir().unwrap();
    let stage = AppStage::fixture(root.path()).unwrap();
    let mut download = stage.create_archive().unwrap();
    download.append(&bytes).unwrap();
    assert!(
        prepare_app_candidate(
            download.finish_manual_import().unwrap(),
            &stage,
            &InstallAuthority::ManualImport
        )
        .is_ok()
    );
}

#[test]
fn candidate_version_is_bounded_regular_utf8_and_semver() {
    for bytes in [
        b"2.0.43\n".as_slice(),
        b"not-version",
        b"",
        &[0xff],
        &[b'1'; 129],
    ] {
        let root = tempdir().unwrap();
        fs::write(root.path().join("version"), bytes).unwrap();
        assert_eq!(
            read_candidate_version(root.path()).is_ok(),
            bytes == b"2.0.43\n"
        );
    }
    let root = tempdir().unwrap();
    assert!(read_candidate_version(root.path()).is_err());
    let outside = tempdir().unwrap();
    fs::write(outside.path().join("version"), b"2.0.43").unwrap();
    std::os::unix::fs::symlink(outside.path().join("version"), root.path().join("version"))
        .unwrap();
    assert!(read_candidate_version(root.path()).is_err());
    fs::remove_file(root.path().join("version")).unwrap();
    fs::create_dir(root.path().join("version")).unwrap();
    assert!(read_candidate_version(root.path()).is_err());
    fs::remove_dir(root.path().join("version")).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        root.path().join("version"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    assert!(read_candidate_version(root.path()).is_err());
}
