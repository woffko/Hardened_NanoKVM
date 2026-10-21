use super::*;

#[test]
fn prior_lifecycle_epochs_cannot_authorize_the_picoclaw_service_transition() {
    assert_eq!(abi::CURRENT.native_lifecycle, 8);
    let current = catalog_fixture();
    for epoch in [1, 2, 3, 4, 5, 6, 7] {
        let mut old = catalog_fixture();
        for member in &mut old.members {
            member.declaration.epochs.native_lifecycle = epoch;
        }
        assert_eq!(
            check_transition(&old, &current),
            Err(CompatibilityError::UnknownOrIncompatible)
        );
        assert_eq!(
            check_transition(&current, &old),
            Err(CompatibilityError::UnknownOrIncompatible)
        );
    }
    assert_eq!(
        check_transition(&current, &current),
        Err(CompatibilityError::UnsupportedTransition)
    );
}
use crate::update::{app_bootstrap::BOOT_SCRIPT_FRAMES, restore_binding};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};

fn file(bytes: &[u8]) -> File {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(bytes).unwrap();
    file
}

fn declarations() -> [Vec<u8>; 6] {
    abi::ROLES.map(|role| abi::encode(role).to_vec())
}

fn helper_frames(declarations: &[Vec<u8>; 6], padding: Option<(usize, usize)>) -> Vec<u8> {
    let originals = helper_family::candidate_files_fixture();
    let mut frames = Vec::new();
    for (index, role) in abi::ROLES[1..].iter().enumerate() {
        let name = format!("kvmapp/system/bin/{}", role.filename());
        let mut image = originals
            .iter()
            .find(|(n, _)| n == &name)
            .unwrap()
            .1
            .clone();
        if let Some((selected, size)) = padding
            && index == selected
        {
            image.resize(size, 0);
        }
        image.extend_from_slice(&declarations[index + 1]);
        let magic = if index == 0 {
            restore_binding::APP_RECOVERY_MAGIC
        } else {
            restore_binding::NATIVE_RUNTIMES[index - 1].magic()
        };
        frames.extend_from_slice(magic);
        frames.extend_from_slice(&(image.len() as u64).to_le_bytes());
        frames.extend_from_slice(&Sha256::digest(&image));
        frames.extend_from_slice(&image);
    }
    frames
}

fn backend_with(declarations: &[Vec<u8>; 6]) -> Vec<u8> {
    let mut bytes = helper_frames(declarations, None);
    bytes.extend_from_slice(&BOOT_SCRIPT_FRAMES.concat());
    bytes.extend_from_slice(&declarations[0]);
    bytes
}

fn backend() -> Vec<u8> {
    backend_with(&declarations())
}

pub(crate) fn catalog_fixture() -> Catalog {
    inspect(&file(&backend())).unwrap()
}

fn rehash(frame: &mut [u8]) {
    let mut hash = Sha256::new();
    hash.update(b"NanoKVM support ABI descriptor v1\0");
    hash.update(&frame[..96]);
    frame[96..].copy_from_slice(&hash.finalize());
}

#[test]
fn complete_catalog_has_six_scoped_roles_and_never_enables_matching_zero() {
    let catalog = catalog_fixture();
    for (member, role) in catalog.members().iter().zip(abi::ROLES) {
        assert_eq!(
            member.declaration(),
            abi::Declaration {
                role,
                epochs: abi::CURRENT
            }
        );
    }
    assert_eq!(
        check_transition(&catalog, &catalog),
        Err(CompatibilityError::UnsupportedTransition)
    );
    let mut fake_live = abi::CURRENT;
    fake_live.support_transition = 1;
    assert_eq!(
        check_with_live(&catalog, &catalog, fake_live),
        Err(CompatibilityError::UnknownOrIncompatible)
    );
}

#[test]
fn every_role_is_required_unique_and_in_its_own_image_scope() {
    for index in 0..6 {
        let mut members = declarations();
        members[index].clear();
        assert!(
            inspect(&file(&backend_with(&members))).is_err(),
            "missing {index}"
        );
        let mut bytes = backend_with(&members);
        bytes.extend_from_slice(&abi::encode(abi::ROLES[index]));
        assert_eq!(
            inspect(&file(&bytes)).is_ok(),
            index == 0,
            "wrong scope {index}"
        );
        let mut members = declarations();
        members[index].extend_from_slice(&abi::encode(abi::ROLES[index]));
        assert!(
            inspect(&file(&backend_with(&members))).is_err(),
            "duplicate {index}"
        );
        for wrong in abi::ROLES {
            if wrong != abi::ROLES[index] {
                let mut members = declarations();
                members[index] = abi::encode(wrong).to_vec();
                assert!(
                    inspect(&file(&backend_with(&members))).is_err(),
                    "{index}, {wrong:?}"
                );
            }
        }
    }
    let mut members = declarations();
    let misplaced = members[0].clone();
    members[1].extend_from_slice(&misplaced);
    members[0].clear();
    assert!(
        inspect(&file(&backend_with(&members))).is_err(),
        "backend declaration inside helper is not top-level"
    );
    assert!(
        inspect(&file(&abi::encode(abi::Role::Backend))).is_err(),
        "complete helper/script families required"
    );
}

#[test]
fn unknown_checksummed_declarations_cannot_hide_behind_a_good_alternative() {
    for index in 0..6 {
        for offset in [8, 9, 10, 11, 12, 13, 15, 36, 95] {
            let mut members = declarations();
            members[index][offset] = if offset == 12 {
                0
            } else {
                members[index][offset] ^ 1
            };
            rehash(&mut members[index]);
            assert!(abi::checksummed(&members[index]));
            members[index].extend_from_slice(&abi::encode(abi::ROLES[index]));
            assert!(
                inspect(&file(&backend_with(&members))).is_err(),
                "{index}, unknown {offset}"
            );
        }
    }
}

#[test]
fn unknown_or_mixed_group_epochs_remain_visible_and_refuse_compatibility() {
    let good = catalog_fixture();
    for index in 0..6 {
        for group in 0..5 {
            let mut members = declarations();
            let offset = 16 + 4 * group;
            members[index][offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            rehash(&mut members[index]);
            let catalog = inspect(&file(&backend_with(&members))).unwrap();
            assert_ne!(catalog.members[index].declaration.epochs, abi::CURRENT);
            for (before, after) in [(&good, &catalog), (&catalog, &good)] {
                assert_eq!(
                    check_transition(before, after),
                    Err(CompatibilityError::UnknownOrIncompatible)
                );
            }
        }
    }
}

#[test]
fn checksum_valid_unknown_abi_inside_script_data_is_not_a_backend_declaration() {
    // A known-format descriptor contains NULs and cannot be a valid script
    // body. Construct checksum-valid UNKNOWN, all-nonzero data instead; this
    // synthetic script is never executed and supplies no update authority.
    assert!(abi::encode(abi::Role::Backend).contains(&0));
    let mut marker = [b'A'; abi::BYTES];
    marker[..8].copy_from_slice(abi::MAGIC);
    let mut found = false;
    for counter in 1..=u8::MAX {
        marker[95] = counter;
        rehash(&mut marker);
        if !marker.contains(&0) {
            found = true;
            break;
        }
    }
    assert!(found);
    assert!(abi::checksummed(&marker));
    assert!(abi::decode(&marker).is_err());
    let mut body = b"#!/bin/sh\n# scoped synthetic data, not executed: ".to_vec();
    body.extend_from_slice(&marker);
    body.push(b'\n');
    let mut script = boot_script_catalog::Role::AppRecovery.magic().to_vec();
    script.extend_from_slice(&(body.len() as u64).to_le_bytes());
    script.extend_from_slice(&Sha256::digest(&body));
    script.extend_from_slice(&body);
    for top_level in [false, true] {
        let members = declarations();
        let mut bytes = helper_frames(&members, None);
        bytes.extend_from_slice(&script);
        for frame in &BOOT_SCRIPT_FRAMES[1..] {
            bytes.extend_from_slice(frame);
        }
        if top_level {
            bytes.extend_from_slice(&members[0]);
        }
        assert_eq!(inspect(&file(&bytes)).is_ok(), top_level);
    }
}

#[test]
fn checksummed_declaration_crossing_a_script_tail_cannot_hide_behind_scope_exclusion() {
    let members = declarations();
    for shared in 1..=abi::MAGIC.len() {
        let mut body = b"#!/bin/sh\n# synthetic shared boundary: ".to_vec();
        body.extend_from_slice(&members[0][..shared]);
        let mut script = boot_script_catalog::Role::AppRecovery.magic().to_vec();
        script.extend_from_slice(&(body.len() as u64).to_le_bytes());
        script.extend_from_slice(&Sha256::digest(&body));
        script.extend_from_slice(&body);
        let mut bytes = helper_frames(&members, None);
        bytes.extend_from_slice(&script);
        bytes.extend_from_slice(&members[0][shared..]);
        for frame in &BOOT_SCRIPT_FRAMES[1..] {
            bytes.extend_from_slice(frame);
        }
        bytes.extend_from_slice(&members[0]);
        // Both outer families are valid and a second backend ABI is present.
        // The checksummed crossing, not a missing family, must cause refusal.
        boot_script_catalog::inspect(&file(&bytes)).unwrap();
        assert!(inspect(&file(&bytes)).is_err(), "shared {shared} bytes");
    }
}

#[test]
fn corrupt_and_truncated_frames_cannot_complete_the_catalog() {
    for index in 0..6 {
        for offset in [0, 8, 12, 16, 35, 95, 96, abi::BYTES - 1] {
            let mut members = declarations();
            members[index][offset] ^= 1;
            assert!(inspect(&file(&backend_with(&members))).is_err());
        }
        for length in [0, 7, 8, 95, 96, abi::BYTES - 1] {
            let mut members = declarations();
            members[index].truncate(length);
            assert!(inspect(&file(&backend_with(&members))).is_err());
        }
    }
}

#[test]
fn invalid_marker_literals_are_bounded_per_scope_and_valid_later_frames_work() {
    for index in 0..6 {
        let mut literal = [0; abi::BYTES];
        literal[..8].copy_from_slice(abi::MAGIC);
        let mut members = declarations();
        let current = members[index].clone();
        members[index] = literal.repeat(MAX_MARKERS - 1);
        members[index].extend_from_slice(&current);
        inspect(&file(&backend_with(&members))).unwrap();
        members[index].extend_from_slice(&literal);
        assert!(inspect(&file(&backend_with(&members))).is_err());
    }
}

#[test]
fn magic_and_frame_boundaries_work_in_backend_and_helper_images() {
    for start in CHUNK - abi::BYTES + 1..=CHUNK + 8 {
        let members = declarations();
        let mut bytes = helper_frames(&members, None);
        bytes.extend_from_slice(&BOOT_SCRIPT_FRAMES.concat());
        assert!(bytes.len() < start);
        bytes.resize(start, 0);
        bytes.extend_from_slice(&members[0]);
        let catalog = inspect(&file(&bytes)).unwrap();
        assert_eq!(catalog.members[0].start, start as u64);
    }
    for selected in 0..5 {
        for padding in CHUNK - abi::BYTES..=CHUNK + 8 {
            let members = declarations();
            let mut bytes = helper_frames(&members, Some((selected, padding)));
            bytes.extend_from_slice(&BOOT_SCRIPT_FRAMES.concat());
            bytes.extend_from_slice(&members[0]);
            inspect(&file(&bytes)).unwrap();
        }
    }
}

#[test]
fn range_checks_refuse_helper_headers_and_even_one_byte_crossing_a_scope() {
    let bytes = backend();
    let source = file(&bytes);
    let helpers = helper_family::inspect(&source).unwrap();
    let scripts = boot_script_catalog::inspect(&source).unwrap();
    for (index, helper) in helpers.members().iter().enumerate() {
        let range = helper.image_range();
        assert_eq!(scope(range.start, &helpers), index + 1);
        assert_eq!(scope(range.start - 1, &helpers), 0);
        check_region(index + 1, range.start, range.end, &helpers, &scripts).unwrap();
        assert!(check_region(index + 1, range.start - 1, range.end, &helpers, &scripts).is_err());
        assert!(check_region(index + 1, range.start, range.end + 1, &helpers, &scripts).is_err());
        assert!(check_region(0, range.start - 1, range.start, &helpers, &scripts).is_err());
        assert!(check_region(0, range.end - 1, range.end, &helpers, &scripts).is_err());
    }
    let catalog = inspect(&source).unwrap();
    check_region(
        0,
        catalog.members[0].start,
        catalog.members[0].end,
        &helpers,
        &scripts,
    )
    .unwrap();
    let script_start = bytes
        .windows(8)
        .position(|bytes| bytes == crate::update::boot_script_catalog::Role::AppRecovery.magic())
        .unwrap() as u64;
    assert!(check_region(0, script_start - 1, script_start + 1, &helpers, &scripts).is_err());
}

#[test]
fn every_source_io_failure_and_changed_scan_header_propagate() {
    let bytes = backend();
    let source = file(&bytes);
    let helpers = helper_family::inspect(&source).unwrap();
    let scripts = boot_script_catalog::inspect(&source).unwrap();
    let mut calls = 0;
    inspect_with(bytes.len() as u64, &helpers, &scripts, |out, offset| {
        calls += 1;
        out.copy_from_slice(&bytes[offset as usize..offset as usize + out.len()]);
        Ok(())
    })
    .unwrap();
    for failed in 0..calls {
        let mut call = 0;
        let error = inspect_with(bytes.len() as u64, &helpers, &scripts, |out, offset| {
            let current = call;
            call += 1;
            if current == failed {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            out.copy_from_slice(&bytes[offset as usize..offset as usize + out.len()]);
            Ok(())
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(call, failed + 1);
    }
    let error = inspect_with(bytes.len() as u64, &helpers, &scripts, |out, offset| {
        out.copy_from_slice(&bytes[offset as usize..offset as usize + out.len()]);
        if out.len() == abi::BYTES {
            out[0] ^= 1;
        }
        Ok(())
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn fixed_buffer_maximal_scan_bounds_and_positional_cursor_are_preserved() {
    let mut source = file(&backend());
    let helpers = helper_family::inspect(&source).unwrap();
    let scripts = boot_script_catalog::inspect(&source).unwrap();
    for size in [0, 63, helper_family::MAX_BACKEND_BYTES + 1, u64::MAX] {
        assert!(inspect_with(size, &helpers, &scripts, |_, _| panic!("must not read")).is_err());
    }
    let mut reads = 0;
    assert!(
        inspect_with(
            helper_family::MAX_BACKEND_BYTES,
            &helpers,
            &scripts,
            |out, offset| {
                reads += 1;
                assert!(out.len() <= CHUNK + 7);
                assert!(offset + out.len() as u64 <= helper_family::MAX_BACKEND_BYTES);
                out.fill(0);
                Ok(())
            }
        )
        .is_err()
    );
    assert_eq!(reads, helper_family::MAX_BACKEND_BYTES as usize / CHUNK);
    source.seek(SeekFrom::Start(37)).unwrap();
    let mut alias = source.try_clone().unwrap();
    inspect(&source).unwrap();
    assert_eq!(source.stream_position().unwrap(), 37);
    assert_eq!(alias.stream_position().unwrap(), 37);
    assert!(inspect(&File::open(tempfile::tempdir().unwrap().path()).unwrap()).is_err());
}

#[test]
#[ignore = "requires fresh six-production-ELF build with ABI declarations"]
fn linked_six_scoped_declarations_match_independent_actual_helper_images() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let backend =
        File::open(root.join("target/riscv64gc-unknown-linux-musl/release/nanokvm-rust-server"))
            .unwrap();
    let catalog = inspect(&backend).unwrap();
    for (member, role) in catalog.members().iter().zip(abi::ROLES) {
        assert_eq!(
            member.declaration(),
            abi::Declaration {
                role,
                epochs: abi::CURRENT
            }
        );
    }
    let helpers = helper_family::inspect(&backend).unwrap();
    for (member, role) in helpers.members().iter().zip(abi::ROLES[1..].iter()) {
        let mut source = File::open(
            root.join("target/restore-runtime/riscv64gc-unknown-linux-musl/release")
                .join(role.filename()),
        )
        .unwrap();
        assert_eq!(source.metadata().unwrap().len(), member.size());
        let mut image = vec![0; member.size() as usize];
        source.read_exact(&mut image).unwrap();
        assert_eq!(source.read(&mut [0; 1]).unwrap(), 0);
        assert_eq!(<[u8; 32]>::from(Sha256::digest(&image)), *member.sha256());
        let mut embedded = vec![0; image.len()];
        backend
            .read_exact_at(&mut embedded, member.image_range().start)
            .unwrap();
        assert_eq!(embedded, image);
    }
    assert_eq!(
        check_transition(&catalog, &catalog),
        Err(CompatibilityError::UnsupportedTransition)
    );
}

#[test]
#[ignore = "requires retained support-ABI development app archives"]
fn historical_packaged_abi_survives_preflight_but_never_matches_current_lifecycle() {
    use crate::{api::application::manual_candidate_fixture, update::app_stage::AppStage};
    use std::{fs, path::Path};

    // These exact-hash retained archives predate the Pico lifecycle protocol.
    // They are historical fixtures, not current-source packaging acceptance.
    // Keep their independently pinned contract instead of relabelling them
    // with CURRENT whenever the executing source's lifecycle epoch changes.
    const ARCHIVED_EPOCHS: abi::Epochs = abi::Epochs {
        app_storage: 1,
        native_lifecycle: 1,
        helper_framing: 1,
        boot_script_framing: 1,
        support_transition: 0,
    };
    const ARCHIVED_SCRIPTS: [(boot_script_catalog::Role, u64, &str); 4] = [
        (
            boot_script_catalog::Role::AppRecovery,
            430,
            "55d3da11e753a73989e4aeb68046f0af8d184ff80ed72052ab7795cb21ca3abb",
        ),
        (
            boot_script_catalog::Role::Ethernet,
            8586,
            "875de81875aa53bfdbe0c976f1876f1314d1a2e495a8623b08b479508c0b717c",
        ),
        (
            boot_script_catalog::Role::Wifi,
            4725,
            "b73af15f74c830137d507e0e7693b97b6d8e42b9219311dd95d9b70592587092",
        ),
        (
            boot_script_catalog::Role::NanoKvm,
            18189,
            "a64e20557759bbfc4541da2eb55e140bcd8068e13a7f2a39ede4e3787ba6a0be",
        ),
    ];
    let current = catalog_fixture();
    let project = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    for (generation, size, sha256) in [
        (
            "valid",
            17_979_230_usize,
            "f709cdf12e4042c9908a50d03d69ee4e87c6a33f08128c80bf1b993236ee7491",
        ),
        (
            "current",
            17_979_593_usize,
            "e73ddb41f95c691406e51ce44bcd913294304b24497a028ccdab3e522b366ccb",
        ),
        (
            "recovery",
            18_127_517_usize,
            "c5f44e96170d267ea608afc0543b3cf2bd4538247793005529551380fb5d39a0",
        ),
        (
            "capacity",
            18_127_834_usize,
            "2e7ccbe875faf96662fdc3c64b4d556862d26329c439787612b89a3f291d34c6",
        ),
    ] {
        for side in ["a", "b"] {
            let archive = project.join(format!(
            "build/audit/remediation-2026-10-17/host/support-abi-candidate-{generation}-{side}/out/support-abi-fixture.tar.gz"
        ));
            let mut source = File::open(archive).unwrap();
            assert_eq!(source.metadata().unwrap().len(), size as u64);
            let mut bytes = vec![0; size];
            source.read_exact(&mut bytes).unwrap();
            assert_eq!(source.read(&mut [0; 1]).unwrap(), 0);
            assert_eq!(format!("{:x}", Sha256::digest(&bytes)), sha256);
            let root = tempfile::tempdir().unwrap();
            fs::create_dir(root.path().join("kvmapp")).unwrap();
            fs::write(root.path().join("kvmapp/identity"), b"old app unchanged").unwrap();
            fs::create_dir_all(root.path().join("etc/init.d")).unwrap();
            for role in boot_script_catalog::ROLES {
                fs::write(
                    root.path().join("etc/init.d").join(role.filename()),
                    b"old gate unchanged",
                )
                .unwrap();
            }
            let candidate =
                manual_candidate_fixture(AppStage::fixture(root.path()).unwrap(), &bytes).unwrap();
            let app = candidate.fixture_root();
            let backend = File::open(app.join("server/NanoKVM-Server")).unwrap();
            let catalog = inspect(&backend).unwrap();
            for (member, role) in catalog.members().iter().zip(abi::ROLES) {
                assert_eq!(
                    member.declaration(),
                    abi::Declaration {
                        role,
                        epochs: ARCHIVED_EPOCHS
                    }
                );
            }
            for (predecessor, successor) in [
                (&catalog, &catalog),
                (&catalog, &current),
                (&current, &catalog),
            ] {
                assert_eq!(
                    check_transition(predecessor, successor),
                    Err(CompatibilityError::UnknownOrIncompatible)
                );
            }
            let scripts = boot_script_catalog::inspect(&backend).unwrap();
            for (member, (role, size, digest)) in scripts.members().iter().zip(ARCHIVED_SCRIPTS) {
                assert_eq!(member.role(), role);
                assert_eq!(member.size(), size);
                let mut payload = vec![0; size as usize];
                backend
                    .read_exact_at(&mut payload, member.payload_range().start)
                    .unwrap();
                let actual = Sha256::digest(&payload);
                assert_eq!(*member.sha256(), <[u8; 32]>::from(actual));
                assert_eq!(format!("{actual:x}"), digest);
                assert_eq!(
                    fs::read(root.path().join("etc/init.d").join(role.filename())).unwrap(),
                    b"old gate unchanged"
                );
            }
            assert_eq!(fs::read(app.join("version")).unwrap(), b"0.0.0\n");
            for name in ["S02apprecover", "S30eth", "S30wifi"] {
                assert!(!app.join("system/init.d").join(name).exists());
            }
            assert_eq!(
                format!(
                    "{:x}",
                    Sha256::digest(fs::read(app.join("system/init.d/S95nanokvm")).unwrap())
                ),
                "8030d0f81581a417eca91e3db7e0c3d96cba197b519022d7c73c3c5caca05365"
            );
            assert_eq!(
                fs::read(root.path().join("kvmapp/identity")).unwrap(),
                b"old app unchanged"
            );
            assert!(!root.path().join("usr/libexec").exists());
            assert!(!root.path().join("application-slot").exists());
        }
    }
}
