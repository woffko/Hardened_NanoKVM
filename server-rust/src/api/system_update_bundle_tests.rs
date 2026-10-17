use super::*;
use crate::api::system_update::{self, SystemManifestFile};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::Sha512;
use std::{fs, io::Write, process::Command};
use tempfile::tempdir;

struct Member {
    name: String,
    kind: u8,
    bytes: Vec<u8>,
    declared: Option<u64>,
}

impl Member {
    fn file(name: &str, bytes: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            kind: b'0',
            bytes,
            declared: None,
        }
    }

    fn directory(name: &str) -> Self {
        Self {
            kind: b'5',
            ..Self::file(name, Vec::new())
        }
    }
}

struct Fixture {
    manifest: SystemManifest,
    expanded: [Vec<u8>; 2],
    stored: [Vec<u8>; 2],
}

impl Fixture {
    fn new(compressed: [bool; 2]) -> Self {
        Self::with_sizes(compressed, [1025, 8193])
    }

    fn with_sizes(compressed: [bool; 2], sizes: [usize; 2]) -> Self {
        let mut manifest = system_update::tests::valid_raw_manifest();
        // The fixture and returned descriptors use BOOT, ROOTFS order, but
        // historical producers list ROOTFS before BOOT in the JSON and tar.
        manifest.raw_images.swap(0, 1);
        let expanded = sizes.map(|size| (0..size).map(|i| (i % 251) as u8).collect::<Vec<_>>());
        let stored = std::array::from_fn(|index| {
            if compressed[index] {
                gzip(&expanded[index])
            } else {
                expanded[index].clone()
            }
        });
        for (index, image) in manifest.raw_images.iter_mut().enumerate() {
            image.size = expanded[index].len() as u64;
            image.sha256 = digest(&expanded[index]);
            if compressed[index] {
                image.payload.push_str(".gz");
                image.compression = Some("gzip".into());
                image.compressed_size = Some(stored[index].len() as u64);
                image.compressed_sha256 = Some(digest(&stored[index]));
            }
        }
        Self {
            manifest,
            expanded,
            stored,
        }
    }

    fn members(&self) -> Vec<Member> {
        vec![
            Member::file("manifest.json", serde_json::to_vec(&self.manifest).unwrap()),
            Member::directory("payload/"),
            Member::directory("payload/images/"),
            Member::file(
                &format!("payload/{}", self.manifest.raw_images[1].payload),
                self.stored[1].clone(),
            ),
            Member::file(
                &format!("payload/{}", self.manifest.raw_images[0].payload),
                self.stored[0].clone(),
            ),
        ]
    }
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn tar(members: &[Member], gnu: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    for member in members {
        let mut header = if gnu {
            tar::Header::new_gnu()
        } else {
            tar::Header::new_ustar()
        };
        header.set_size(member.declared.unwrap_or(member.bytes.len() as u64));
        header.set_entry_type(tar::EntryType::new(member.kind));
        header.set_mode(if member.kind == b'5' { 0o700 } else { 0o600 });
        let mut block = *header.as_bytes();
        // Deliberately do not call set_path: it rejects/normalizes adversarial
        // names before they reach the parser being tested.
        assert!(member.name.len() < 100);
        block[..100].fill(0);
        block[..member.name.len()].copy_from_slice(member.name.as_bytes());
        fix_checksum(&mut block);
        bytes.extend_from_slice(&block);
        bytes.extend_from_slice(&member.bytes);
        bytes.resize(bytes.len().next_multiple_of(BLOCK), 0);
    }
    bytes.resize(bytes.len() + 2 * BLOCK, 0);
    bytes
}

fn latest(bytes: &[u8], manifest: &SystemManifest) -> SystemLatest {
    let mut latest = system_update::tests::valid_latest();
    latest.version = manifest.version.clone();
    latest.format = if manifest.format.ends_with("-v2") {
        2
    } else {
        1
    };
    latest.required_app_version = manifest.required_app_version.clone();
    latest.size = bytes.len() as u64;
    latest.sha256 = digest(bytes);
    latest.sha512 = STANDARD.encode(Sha512::digest(bytes));
    latest
}

fn snapshot(stage: &StageDirectory, bytes: &[u8]) -> PublicSnapshot {
    PublicSnapshot::capture(
        stage,
        &mut io::Cursor::new(bytes),
        bytes.len() as u64,
        &Sha256::digest(bytes).into(),
        &Sha512::digest(bytes).into(),
    )
    .unwrap()
}

fn rejected_bytes(bytes: &[u8], manifest: &SystemManifest) {
    let root = tempdir().unwrap();
    let path = root.path().join("system");
    let stage = StageDirectory::prepare(&path).unwrap();
    let mut source = snapshot(&stage, bytes);
    assert!(capture(&mut source, &stage, &latest(bytes, manifest)).is_err());
    assert_eq!(fs::read_dir(path).unwrap().count(), 0);
}

fn rejected(members: &[Member], manifest: &SystemManifest) {
    rejected_bytes(&gzip(&tar(members, false)), manifest);
}

#[test]
fn bounded_bundle_captures_plain_gzip_and_mixed_images_in_canonical_order() {
    for compressed in [[false, false], [true, true], [true, false], [false, true]] {
        for gnu in [false, true] {
            let fixture = Fixture::new(compressed);
            let mut members = fixture.members();
            if gnu {
                members.swap(3, 4);
            }
            let mut manifest = fixture.manifest.clone();
            manifest.raw_images.swap(0, 1);
            members[0].bytes = serde_json::to_vec(&manifest).unwrap();
            let bytes = gzip(&tar(&members, gnu));
            let root = tempdir().unwrap();
            let path = root.path().join("system");
            let stage = StageDirectory::prepare(&path).unwrap();
            let mut source = snapshot(&stage, &bytes);
            let result = capture(&mut source, &stage, &latest(&bytes, &manifest)).unwrap();
            assert_eq!(result.manifest, manifest);
            let images = result.raw_images.unwrap();
            for (mut image, expected) in images.into_iter().zip(&fixture.expanded) {
                let mut actual = Vec::new();
                image.read_to_end(&mut actual).unwrap();
                assert_eq!(&actual, expected);
                image.rewind().unwrap();
                let mut first = [0; 1];
                image.read_exact(&mut first).unwrap();
                assert_eq!(first[0], expected[0]);
            }
            assert_eq!(fs::read_dir(path).unwrap().count(), 0);
        }
    }
}

#[test]
fn manifest_v2_required_app_and_signed_metadata_identity_are_checked() {
    let mut fixture = Fixture::new([true, true]);
    fixture.manifest.format = "hardened-nanokvm-system-update-v2".into();
    fixture.manifest.required_app_version = Some("2.0.42".into());
    let bytes = gzip(&tar(&fixture.members(), false));
    let root = tempdir().unwrap();
    let stage = StageDirectory::prepare(&root.path().join("system")).unwrap();
    let mut source = snapshot(&stage, &bytes);
    let metadata = latest(&bytes, &fixture.manifest);
    assert!(capture(&mut source, &stage, &metadata).is_ok());
    for case in 0..4 {
        let mut wrong = metadata.clone();
        match case {
            0 => wrong.required_app_version = Some("2.0.40".into()),
            1 => wrong.target.push_str("-other"),
            2 => wrong.version.push_str("-other"),
            3 => wrong.format = 1,
            _ => unreachable!(),
        }
        assert!(capture(&mut source, &stage, &wrong).is_err());
    }
}

#[test]
fn raw_set_rejects_missing_duplicate_mixed_and_over_budget_targets() {
    for case in 0..7 {
        let mut fixture = Fixture::new([true, true]);
        match case {
            0 => {
                fixture.manifest.raw_images.pop();
            }
            1 => fixture.manifest.raw_images[1] = fixture.manifest.raw_images[0].clone(),
            2 => fixture.manifest.files.push(SystemManifestFile {
                payload: "rootfs/etc/os-release".into(),
                install: "/etc/os-release".into(),
                size: 1,
                sha256: "a".repeat(64),
            }),
            3 => fixture.manifest.raw_images[0].device = "/dev/mmcblk0p3".into(),
            4 => fixture.manifest.raw_images[0].size = MAX_SYSTEM_UPDATE_PAYLOAD_BYTES,
            5 => {
                fixture.manifest.raw_images[0].compressed_size =
                    Some(MAX_SYSTEM_UPDATE_PAYLOAD_BYTES)
            }
            6 => fixture.manifest.raw_images[0].size = u64::MAX,
            _ => unreachable!(),
        }
        // Build entries independently, so malformed manifests never index a
        // missing image in the fixture helper or allocate declared image sizes.
        let mut members = Fixture::new([true, true]).members();
        members[0].bytes = serde_json::to_vec(&fixture.manifest).unwrap();
        rejected(&members, &fixture.manifest);
    }
}

#[test]
fn exactly_the_two_image_and_two_directory_members_are_admitted() {
    let fixture = Fixture::new([false, false]);
    for case in 0..10 {
        let mut members = fixture.members();
        match case {
            0 => {
                members.remove(1);
            }
            1 => members[2].name = "payload/".into(),
            2 => members[4].name = members[3].name.clone(),
            3 => members[3].name = "payload/images/../rootfs.sd".into(),
            4 => members[3].name.insert(0, '/'),
            5 => members[3].name = "payload/./images/rootfs.sd".into(),
            6 => members.push(Member::file("extra", vec![1])),
            7 => members[3].name = "manifest.json".into(),
            8 => members[1].bytes.push(0),
            9 => members.swap(0, 1),
            _ => unreachable!(),
        }
        rejected(&members, &fixture.manifest);
    }
}

#[test]
fn extension_links_sparse_devices_and_unknown_types_are_rejected_before_body_read() {
    let fixture = Fixture::new([false, false]);
    for kind in *b"123467LKxgSZ" {
        let mut members = fixture.members();
        members[3].kind = kind;
        members[3].declared = Some(MAX_SYSTEM_UPDATE_PAYLOAD_BYTES);
        members[3].bytes.clear();
        let bytes = gzip(&tar(&members, false));
        let root = tempdir().unwrap();
        let stage = StageDirectory::prepare(&root.path().join("system")).unwrap();
        let mut source = snapshot(&stage, &bytes);
        let error = capture(&mut source, &stage, &latest(&bytes, &fixture.manifest))
            .err()
            .unwrap();
        assert!(
            matches!(error, AppError::BadRequest(_)),
            "extension body was read"
        );
    }
}

#[test]
fn raw_and_compressed_digests_and_both_sizes_are_checked() {
    for compressed in [[false, false], [true, true]] {
        for case in 0..6 {
            let mut fixture = Fixture::new(compressed);
            match case {
                0 => fixture.manifest.raw_images[0].sha256 = "a".repeat(64),
                1 => fixture.manifest.raw_images[0].size -= 1,
                2 => fixture.manifest.raw_images[0].size += 1,
                3 if compressed[0] => {
                    fixture.manifest.raw_images[0].compressed_sha256 = Some("a".repeat(64))
                }
                4 if compressed[0] => {
                    *fixture.manifest.raw_images[0]
                        .compressed_size
                        .as_mut()
                        .unwrap() -= 1;
                }
                5 if compressed[0] => {
                    *fixture.manifest.raw_images[0]
                        .compressed_size
                        .as_mut()
                        .unwrap() += 1;
                }
                _ => {
                    fixture.stored[0][0] ^= 1;
                }
            }
            rejected(&fixture.members(), &fixture.manifest);
        }
    }
}

#[test]
fn inner_gzip_requires_crc_isize_eof_and_exactly_one_member() {
    for case in 0..6 {
        let mut fixture = Fixture::new([true, true]);
        let stored = &mut fixture.stored[0];
        let length = stored.len();
        match case {
            0 => stored[length - 8] ^= 1,
            1 => stored[length - 4] ^= 1,
            2 => {
                stored.truncate(length - 1);
            }
            3 => stored.push(0),
            4 => stored.extend(gzip(b"hidden second member")),
            5 => stored.extend(gzip(b"")),
            _ => unreachable!(),
        }
        // Match compressed metadata to the malformed signed member: only
        // decoder/framing proof, not a redundant hash mismatch, may reject it.
        fixture.manifest.raw_images[0].compressed_size = Some(stored.len() as u64);
        fixture.manifest.raw_images[0].compressed_sha256 = Some(digest(stored));
        rejected(&fixture.members(), &fixture.manifest);
    }
}

#[test]
fn outer_gzip_requires_crc_isize_eof_and_exactly_one_member() {
    let fixture = Fixture::new([true, true]);
    let original = gzip(&tar(&fixture.members(), false));
    for case in 0..6 {
        let mut bytes = original.clone();
        let length = bytes.len();
        match case {
            0 => bytes[length - 8] ^= 1,
            1 => bytes[length - 4] ^= 1,
            2 => {
                bytes.truncate(length - 1);
            }
            3 => bytes.push(0),
            4 => bytes.extend(gzip(b"hidden second member")),
            5 => bytes.extend(gzip(b"")),
            _ => unreachable!(),
        }
        // Outer snapshot hashes deliberately authenticate these exact malformed
        // bytes. Signature trust alone must not hide a framing discrepancy.
        rejected_bytes(&bytes, &fixture.manifest);
    }
}

#[test]
fn tar_padding_two_zero_blocks_and_bounded_record_padding_are_required() {
    let fixture = Fixture::new([true, true]);
    let members = fixture.members();
    let original = tar(&members, false);
    for case in 0..8 {
        let mut bytes = original.clone();
        let length = bytes.len();
        match case {
            0 => {
                bytes.truncate(length - 2 * BLOCK);
            }
            1 => {
                bytes.truncate(length - BLOCK);
            }
            2 => bytes.push(0),
            3 => bytes[length - 1] = 1,
            4 => bytes.extend(tar(&[Member::file("hidden", vec![1])], false)),
            5 => bytes[BLOCK + members[0].bytes.len()] = 1,
            6 => bytes[length - 2 * BLOCK - 1] = 1,
            7 => bytes.resize(length + MAX_ZERO_TRAILER, 0),
            _ => unreachable!(),
        }
        rejected_bytes(&gzip(&bytes), &fixture.manifest);
    }
    for extra in [0, BLOCK, 18 * BLOCK] {
        let mut bytes = original.clone();
        bytes.resize(bytes.len() + extra, 0);
        let bytes = gzip(&bytes);
        let root = tempdir().unwrap();
        let stage = StageDirectory::prepare(&root.path().join("system")).unwrap();
        let mut source = snapshot(&stage, &bytes);
        assert!(capture(&mut source, &stage, &latest(&bytes, &fixture.manifest)).is_ok());
    }
}

fn fix_checksum(bytes: &mut [u8]) {
    bytes[148..156].fill(b' ');
    let sum: u32 = bytes[..BLOCK].iter().map(|byte| u32::from(*byte)).sum();
    bytes[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

#[test]
fn raw_headers_reject_checksum_prefix_link_sparse_and_setid_ambiguities() {
    let fixture = Fixture::new([false, false]);
    for gnu in [false, true] {
        for case in 0..6 {
            let mut bytes = tar(&fixture.members(), gnu);
            match case {
                // Change only checksum, leaving the expected name/layout valid.
                0 => bytes[153] = if bytes[153] == b'0' { b'1' } else { b'0' },
                1 => bytes[157] = b'x',
                2 => bytes[if gnu { 386 } else { 345 }] = b'x',
                3 => bytes[100..108].copy_from_slice(b"0004600\0"),
                4 => bytes[14] = b'x', // NUL-tail hidden name bytes.
                5 => {
                    let size = fixture.members()[0].bytes.len() as u64;
                    bytes[124..136].fill(0);
                    bytes[124] = 0x80;
                    bytes[128..136].copy_from_slice(&size.to_be_bytes());
                }
                _ => unreachable!(),
            }
            if case != 0 {
                fix_checksum(&mut bytes);
            }
            rejected_bytes(&gzip(&bytes), &fixture.manifest);
        }
    }
}

#[test]
fn manifest_size_json_and_first_member_are_bounded_before_raw_payload_capture() {
    let fixture = Fixture::new([false, false]);
    for case in 0..5 {
        let mut members = fixture.members();
        match case {
            0 => members[0].declared = Some(MAX_MANIFEST + 1),
            1 => members[0].declared = Some(u64::MAX),
            2 => members[0].bytes.clear(),
            3 => members[0].bytes = b"{ invalid json".to_vec(),
            4 => {
                members[0].bytes.pop();
                members[0]
                    .bytes
                    .extend_from_slice(b",\"version\":\"duplicate\"}");
            }
            _ => unreachable!(),
        }
        rejected(&members, &fixture.manifest);
    }
}

#[test]
fn snapshot_images_do_not_reopen_named_source_or_extracted_payloads() {
    let fixture = Fixture::with_sizes([true, true], [65537, 2 * 1024 * 1024 + 17]);
    let bytes = gzip(&tar(&fixture.members(), false));
    let root = tempdir().unwrap();
    let path = root.path().join("system");
    let stage = StageDirectory::prepare(&path).unwrap();
    let named = path.join("archive.tar.gz");
    fs::write(&named, &bytes).unwrap();
    let mut original = fs::File::open(&named).unwrap();
    let mut source = PublicSnapshot::capture(
        &stage,
        &mut original,
        bytes.len() as u64,
        &Sha256::digest(&bytes).into(),
        &Sha512::digest(&bytes).into(),
    )
    .unwrap();
    fs::write(&named, b"replacement source").unwrap();
    let captured = capture(&mut source, &stage, &latest(&bytes, &fixture.manifest)).unwrap();
    fs::create_dir_all(path.join("extract/payload/images")).unwrap();
    fs::write(
        path.join("extract/payload/images/rootfs.sd"),
        b"untrusted tree",
    )
    .unwrap();
    for (mut image, expected) in captured
        .raw_images
        .unwrap()
        .into_iter()
        .zip(&fixture.expanded)
    {
        let mut actual = Vec::new();
        image.read_to_end(&mut actual).unwrap();
        assert_eq!(&actual, expected);
    }
}

#[test]
fn invalid_raw_preflight_does_not_delete_previous_extraction_or_recovery_evidence() {
    let mut fixture = Fixture::new([true, true]);
    fixture.manifest.raw_images[0].sha256 = "a".repeat(64);
    let bytes = gzip(&tar(&fixture.members(), false));
    let root = tempdir().unwrap();
    let path = root.path().join("system");
    let stage = StageDirectory::prepare(&path).unwrap();
    fs::create_dir(path.join("extract")).unwrap();
    fs::write(path.join("extract/keep"), b"previous recovery evidence").unwrap();
    let mut source = snapshot(&stage, &bytes);
    assert!(
        system_update::extract_and_verify_system_bundle(
            &mut source,
            &path,
            &latest(&bytes, &fixture.manifest),
        )
        .is_err()
    );
    assert_eq!(
        fs::read(path.join("extract/keep")).unwrap(),
        b"previous recovery evidence"
    );
    assert_eq!(fs::read_dir(&path).unwrap().count(), 1);
}

#[test]
fn actual_gnu_tar_producer_layout_with_normal_record_padding_is_compatible() {
    let fixture = Fixture::new([true, true]);
    let root = tempdir().unwrap();
    let input = root.path().join("input");
    fs::create_dir_all(input.join("payload/images")).unwrap();
    fs::write(
        input.join("manifest.json"),
        serde_json::to_vec(&fixture.manifest).unwrap(),
    )
    .unwrap();
    for (image, bytes) in fixture.manifest.raw_images.iter().zip(&fixture.stored) {
        fs::write(input.join("payload").join(&image.payload), bytes).unwrap();
    }
    let output = root.path().join("bundle.tar.gz");
    assert!(
        Command::new("/usr/bin/tar")
            .arg("-C")
            .arg(&input)
            .arg("-czf")
            .arg(&output)
            .args(["manifest.json", "payload"])
            .status()
            .unwrap()
            .success()
    );
    let bytes = fs::read(output).unwrap();
    let stage = StageDirectory::prepare(&root.path().join("system")).unwrap();
    let mut source = snapshot(&stage, &bytes);
    assert!(capture(&mut source, &stage, &latest(&bytes, &fixture.manifest)).is_ok());
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn second_image_failure_cleanup_child_fixture() {
    if std::env::var_os("NANOKVM_BUNDLE_CLEANUP_FIXTURE").is_none() {
        return;
    }
    let mut fixture = Fixture::new([false, false]);
    // ROOTFS is first in the tar and succeeds; the second (BOOT) snapshot
    // fails its digest after allocating/copying an anonymous spool.
    fixture.manifest.raw_images[0].sha256 = "a".repeat(64);
    let bytes = gzip(&tar(&fixture.members(), false));
    let root = tempdir().unwrap();
    let path = root.path().join("system");
    let stage = StageDirectory::prepare(&path).unwrap();
    let mut source = snapshot(&stage, &bytes);
    let count_fds = || fs::read_dir("/proc/self/fd").unwrap().count();
    let before = count_fds();
    assert!(capture(&mut source, &stage, &latest(&bytes, &fixture.manifest)).is_err());
    assert_eq!(count_fds(), before, "anonymous image descriptor leaked");
    assert_eq!(fs::read_dir(path).unwrap().count(), 0);
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn failure_after_first_image_success_releases_all_anonymous_descriptors() {
    // Isolate fd accounting from the parallel test harness and its other
    // snapshot tests. This does not exercise target exFAT/power-loss cleanup.
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "api::system_update::bundle::tests::second_image_failure_cleanup_child_fixture",
            "--nocapture",
        ])
        .env_clear()
        .env("NANOKVM_BUNDLE_CLEANUP_FIXTURE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated descriptor cleanup fixture failed"
    );
}

#[test]
#[ignore = "manual public retained-artifact compatibility check; requires local RC12 assets"]
fn retained_raw12_public_bundle_framing_and_image_snapshots() {
    const ARCHIVE: &str = "hardened-nanokvm-system-0.3.0-raw.12.tar.gz";
    let project = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let release = project.join("build/release/combined-rc12-bridge");
    let metadata: SystemLatest =
        serde_json::from_slice(&fs::read(release.join("system-latest.json")).unwrap()).unwrap();
    // Pin the already retained public artifact, not arbitrary p3 metadata.
    // This fixture does not repeat RSA authentication or device acceptance.
    assert_eq!(
        metadata.sha256,
        "cf6bbef5599197f4b5ed926f22bed12352f2fdc275eb8f32fc8344d3ed7eae96"
    );
    assert_eq!(metadata.size, 57_144_130);
    assert_eq!(metadata.name, ARCHIVE);
    assert_eq!(metadata.version, "0.3.0-raw.12");
    assert_eq!(metadata.required_app_version.as_deref(), Some("2.0.42"));
    let root = tempdir().unwrap();
    let path = root.path().join("system");
    let stage = StageDirectory::prepare(&path).unwrap();
    let mut file = fs::File::open(release.join(ARCHIVE)).unwrap();
    let mut source = system_update::freeze_system_archive(&mut file, &path, &metadata).unwrap();
    let captured = capture(&mut source, &stage, &metadata).unwrap();
    assert_eq!(captured.manifest.version, metadata.version);
    for (mut image, label) in captured
        .raw_images
        .unwrap()
        .into_iter()
        .zip(["BOOT", "ROOTFS"])
    {
        let entry = captured
            .manifest
            .raw_images
            .iter()
            .find(|image| image.label == label)
            .unwrap();
        assert_eq!(image.seek(io::SeekFrom::End(0)).unwrap(), entry.size);
    }
    assert_eq!(fs::read_dir(path).unwrap().count(), 0);
}
