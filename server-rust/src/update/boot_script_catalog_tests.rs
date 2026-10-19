use super::*;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};

fn body(role: Role) -> Vec<u8> {
    format!(
        "#!/bin/sh\n# synthetic boot catalog {}\nexit 0\n",
        role.filename()
    )
    .into_bytes()
}

fn frame(role: Role, body: &[u8]) -> Vec<u8> {
    let mut bytes = role.magic().to_vec();
    bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&Sha256::digest(body));
    bytes.extend_from_slice(body);
    bytes
}

fn frames() -> [Vec<u8>; 4] {
    ROLES.map(|role| frame(role, &body(role)))
}

fn helper_bytes() -> Vec<u8> {
    helper_family::candidate_files_fixture()
        .into_iter()
        .find(|(name, _)| name == "kvmapp/server/NanoKVM-Server")
        .unwrap()
        .1
}

fn file(bytes: &[u8]) -> File {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(bytes).unwrap();
    file
}

fn helpers() -> helper_family::Family {
    helper_family::inspect(&file(&helper_bytes())).unwrap()
}

fn backend() -> Vec<u8> {
    let mut bytes = helper_bytes();
    bytes.extend_from_slice(&frames().concat());
    bytes
}

#[test]
fn build_frames_and_existing_startup_view_share_exact_canonical_source_bytes() {
    use crate::update::app_bootstrap::{BOOT_SCRIPT_FRAMES, BOOT_SCRIPTS};
    assert_eq!(BOOT_SCRIPTS.len(), ROLES.len());
    for ((frame, (name, payload)), role) in BOOT_SCRIPT_FRAMES.iter().zip(BOOT_SCRIPTS).zip(ROLES) {
        assert_eq!(*name, role.filename());
        assert_eq!(binding::validate(frame, role).unwrap(), *payload);
        assert_eq!(
            payload.as_ptr(),
            frame.as_ptr().wrapping_add(binding::HEADER)
        );
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../kvmapp/system/init.d")
            .join(name);
        assert_eq!(std::fs::read(source).unwrap().as_slice(), *payload);
    }
}

#[test]
fn framing_requires_exact_role_size_digest_shebang_and_no_nul() {
    for role in ROLES {
        let good = frame(role, &body(role));
        assert_eq!(binding::validate(&good, role).unwrap(), body(role));
        for other in ROLES {
            if role != other {
                assert!(binding::validate(&good, other).is_err());
            }
        }
        for position in [0, 8, 16, binding::HEADER, good.len() - 1] {
            let mut damaged = good.clone();
            damaged[position] ^= 1;
            assert!(binding::validate(&damaged, role).is_err());
        }
        for bad in [
            b"not a shell script".as_slice(),
            b"#!/bin/sh\n\0hidden",
            b"#!/bin/sh\r\n",
        ] {
            assert!(binding::validate(&frame(role, bad), role).is_err());
        }
        for size in [0, binding::MAX_SCRIPT as u64 + 1, u64::MAX] {
            let mut damaged = good.clone();
            damaged[8..16].copy_from_slice(&size.to_le_bytes());
            assert!(binding::validate(&damaged, role).is_err());
        }
        assert!(binding::validate(&good[..binding::HEADER - 1], role).is_err());
        assert!(binding::validate(&good[..good.len() - 1], role).is_err());
        let mut extra = good;
        extra.push(0);
        assert!(binding::validate(&extra, role).is_err());
    }
}

#[test]
fn complete_catalog_is_fixed_order_diagnostics_not_authentication() {
    let mut bytes = helper_bytes();
    for member in frames().into_iter().rev() {
        bytes.extend_from_slice(&member);
    }
    let catalog = inspect(&file(&bytes)).unwrap();
    for (member, role) in catalog.members().iter().zip(ROLES) {
        assert_eq!(member.role(), role);
        assert_eq!(member.size(), body(role).len() as u64);
        assert_eq!(
            *member.sha256(),
            <[u8; 32]>::from(Sha256::digest(body(role)))
        );
        assert_eq!(
            &bytes[member.start as usize..member.start as usize + 8],
            role.magic()
        );
    }
    assert!(
        inspect(&file(&frames().concat())).is_err(),
        "helpers are mandatory"
    );
}

#[test]
fn every_role_required_and_duplicate_valid_frames_are_ambiguous() {
    for (missing, role) in ROLES.into_iter().enumerate() {
        let mut bytes = helper_bytes();
        for (index, member) in frames().iter().enumerate() {
            if index != missing {
                bytes.extend_from_slice(member);
            }
        }
        assert!(inspect(&file(&bytes)).is_err(), "missing {role:?}");
        for different in [false, true] {
            let mut bytes = backend();
            let regular = body(role);
            bytes.extend_from_slice(&frame(
                role,
                if different {
                    b"#!/bin/sh\nexit 1\n"
                } else {
                    &regular
                },
            ));
            assert!(
                inspect(&file(&bytes)).is_err(),
                "duplicate {role:?}, {different}"
            );
        }
    }
}

#[test]
fn corrupt_truncated_and_invalid_body_frames_cannot_complete_the_catalog() {
    for (index, role) in ROLES.into_iter().enumerate() {
        for position in [8, 16, binding::HEADER, frames()[index].len() - 1] {
            let mut members = frames();
            members[index][position] ^= 1;
            let mut bytes = helper_bytes();
            bytes.extend_from_slice(&members.concat());
            assert!(inspect(&file(&bytes)).is_err(), "{role:?}, byte {position}");
        }
        let mut members = frames();
        members[index] = frame(role, b"#!/bin/sh\n\0not script data");
        let mut bytes = helper_bytes();
        bytes.extend_from_slice(&members.concat());
        assert!(inspect(&file(&bytes)).is_err());
    }
    let bytes = backend();
    for removed in 1..=binding::HEADER + 1 {
        assert!(inspect(&file(&bytes[..bytes.len() - removed])).is_err());
    }
}

#[test]
fn invalid_literals_count_toward_cap_but_do_not_hide_valid_later_frames() {
    for role in ROLES {
        let mut bytes = helper_bytes();
        for _ in 1..MAX_MARKERS {
            bytes.extend_from_slice(role.magic());
            bytes.extend_from_slice(&[0; 40]);
        }
        bytes.extend_from_slice(&frames().concat());
        inspect(&file(&bytes)).unwrap();
        bytes.extend_from_slice(role.magic());
        assert!(inspect(&file(&bytes)).is_err());
    }
}

#[test]
fn every_chunk_boundary_header_and_multichunk_body_are_checked() {
    for role in ROLES {
        for boundary in CHUNK - 47..=CHUNK + 8 {
            let mut bytes = helper_bytes();
            bytes.resize(boundary, 0);
            bytes.extend_from_slice(&frame(role, &body(role)));
            for other in ROLES {
                if other != role {
                    bytes.extend_from_slice(&frame(other, &body(other)));
                }
            }
            inspect(&file(&bytes)).unwrap();
        }
    }
    let mut bytes = helper_bytes();
    for role in ROLES {
        let mut body = body(role);
        body.resize(binding::MAX_SCRIPT, b'#');
        bytes.extend_from_slice(&frame(role, &body));
    }
    let catalog = inspect(&file(&bytes)).unwrap();
    assert!(
        catalog
            .members()
            .iter()
            .all(|member| member.size() == binding::MAX_SCRIPT as u64)
    );
}

#[test]
fn valid_catalogs_inside_helper_images_are_not_top_level_or_duplicates() {
    let original = helper_bytes();
    let old_size = u64::from_le_bytes(original[8..16].try_into().unwrap()) as usize;
    let mut image = original
        [super::super::restore_binding::HEADER..super::super::restore_binding::HEADER + old_size]
        .to_vec();
    image.extend_from_slice(&frames().concat());
    let mut bytes = super::super::restore_binding::APP_RECOVERY_MAGIC.to_vec();
    bytes.extend_from_slice(&(image.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&Sha256::digest(&image));
    bytes.extend_from_slice(&image);
    bytes.extend_from_slice(&original[super::super::restore_binding::HEADER + old_size..]);
    helper_family::inspect(&file(&bytes)).unwrap();
    assert!(
        inspect(&file(&bytes)).is_err(),
        "nested catalog is not the backend catalog"
    );
    bytes.extend_from_slice(&frames().concat());
    inspect(&file(&bytes)).unwrap();
}

#[test]
fn valid_script_frame_cannot_overlap_a_helper_frame_by_even_one_marker() {
    let helpers = helper_bytes();
    let mut script = body(Role::AppRecovery);
    script.extend_from_slice(super::super::restore_binding::APP_RECOVERY_MAGIC);
    let mut bytes = frame(Role::AppRecovery, &script);
    binding::validate(&bytes, Role::AppRecovery).unwrap();
    // Share only the eight non-NUL magic bytes; both individual frames remain
    // valid. The catalog must reject the actual cross-family range overlap.
    bytes.extend_from_slice(&helpers[8..]);
    for role in &ROLES[1..] {
        bytes.extend_from_slice(&frame(*role, &body(*role)));
    }
    helper_family::inspect(&file(&bytes)).unwrap();
    assert!(inspect(&file(&bytes)).is_err());
}

#[test]
fn two_valid_top_level_script_frames_cannot_share_eight_bytes() {
    let mut first_body = body(Role::AppRecovery);
    first_body.extend_from_slice(Role::Ethernet.magic());
    let first = frame(Role::AppRecovery, &first_body);
    binding::validate(&first, Role::AppRecovery).unwrap();
    let second = frame(Role::Ethernet, &body(Role::Ethernet));
    binding::validate(&second, Role::Ethernet).unwrap();
    let mut bytes = helper_bytes();
    bytes.extend_from_slice(&first);
    bytes.extend_from_slice(&second[8..]);
    for role in &ROLES[2..] {
        bytes.extend_from_slice(&frame(*role, &body(*role)));
    }
    assert!(inspect(&file(&bytes)).is_err());
}

#[test]
fn source_io_errors_and_changed_scan_header_are_not_invalid_literal_fallback() {
    let bytes = backend();
    let helpers = helpers();
    let mut reads = Vec::new();
    inspect_with(bytes.len() as u64, &helpers, |out, offset| {
        reads.push((offset, out.len()));
        out.copy_from_slice(&bytes[offset as usize..offset as usize + out.len()]);
        Ok(())
    })
    .unwrap();
    for failed in 0..reads.len() {
        let mut call = 0;
        let error = inspect_with(bytes.len() as u64, &helpers, |out, offset| {
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
    let error = inspect_with(bytes.len() as u64, &helpers, |out, offset| {
        out.copy_from_slice(&bytes[offset as usize..offset as usize + out.len()]);
        if out.len() == binding::HEADER {
            out[0] ^= 1;
        }
        Ok(())
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn size_caps_and_hash_work_are_checked_before_body_reads() {
    for role in ROLES {
        for size in [0, binding::MAX_SCRIPT as u64 + 1, u64::MAX] {
            let mut header = [0; binding::HEADER];
            header[..8].copy_from_slice(role.magic());
            header[8..16].copy_from_slice(&size.to_le_bytes());
            let mut buffer = [0; binding::HEADER + binding::MAX_SCRIPT];
            let mut budget = MAX_HASH_BYTES;
            let mut reads = 0;
            assert!(
                inspect_member(
                    role,
                    0,
                    helper_family::MAX_BACKEND_BYTES,
                    &mut |out, offset| {
                        reads += 1;
                        assert_eq!((offset, out.len()), (0, binding::HEADER));
                        out.copy_from_slice(&header);
                        Ok(())
                    },
                    &mut buffer,
                    &mut budget
                )
                .unwrap()
                .is_none()
            );
            assert_eq!(reads, 1);
            assert_eq!(budget, MAX_HASH_BYTES);
        }
    }
    let role = Role::NanoKvm;
    let bytes = frame(role, &body(role));
    let mut budget = 2 * body(role).len() as u64;
    let mut buffer = [0; binding::HEADER + binding::MAX_SCRIPT];
    for expected_ok in [true, true, false] {
        let mut reads = 0;
        let result = inspect_member(
            role,
            0,
            bytes.len() as u64,
            &mut |out, offset| {
                reads += 1;
                out.copy_from_slice(&bytes[offset as usize..offset as usize + out.len()]);
                Ok(())
            },
            &mut buffer,
            &mut budget,
        );
        assert_eq!(result.is_ok(), expected_ok);
        if !expected_ok {
            assert_eq!(reads, 1);
        }
    }
    assert_eq!(budget, 0);
}

#[test]
fn invalid_backend_bounds_do_not_read_and_maximal_scan_uses_fixed_buffers() {
    let helpers = helpers();
    for size in [0, 63, helper_family::MAX_BACKEND_BYTES + 1, u64::MAX] {
        assert!(inspect_with(size, &helpers, |_, _| panic!("must not read")).is_err());
    }
    let mut reads = 0;
    assert!(
        inspect_with(helper_family::MAX_BACKEND_BYTES, &helpers, |out, offset| {
            reads += 1;
            assert!(out.len() <= CHUNK + 7);
            assert!(offset + out.len() as u64 <= helper_family::MAX_BACKEND_BYTES);
            out.fill(0);
            Ok(())
        })
        .is_err()
    );
    assert_eq!(reads, helper_family::MAX_BACKEND_BYTES as usize / CHUNK);
}

#[test]
fn positional_catalog_inspection_preserves_shared_cursor_and_refuses_directory() {
    let mut file = file(&backend());
    file.seek(SeekFrom::Start(37)).unwrap();
    let mut alias = file.try_clone().unwrap();
    inspect(&file).unwrap();
    assert_eq!(file.stream_position().unwrap(), 37);
    assert_eq!(alias.stream_position().unwrap(), 37);
    assert!(inspect(&File::open(tempfile::tempdir().unwrap().path()).unwrap()).is_err());
}

#[test]
#[ignore = "requires current real linked backend with framed boot catalog"]
fn linked_boot_catalog_matches_actual_canonical_sources_without_installing() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let backend = root.join("target/riscv64gc-unknown-linux-musl/release/nanokvm-rust-server");
    let file = File::open(backend).unwrap();
    let catalog = inspect(&file).unwrap();
    for (member, role) in catalog.members().iter().zip(ROLES) {
        let source =
            std::fs::read(root.join("../kvmapp/system/init.d").join(role.filename())).unwrap();
        assert!(source.len() <= binding::MAX_SCRIPT);
        assert_eq!(member.size(), source.len() as u64);
        assert_eq!(*member.sha256(), <[u8; 32]>::from(Sha256::digest(&source)));
        let mut stored = vec![0; source.len()];
        file.read_exact_at(&mut stored, member.start + binding::HEADER as u64)
            .unwrap();
        assert_eq!(stored, source);
    }
}

#[test]
#[ignore = "requires retained framed-catalog development app archives"]
fn packaged_catalog_survives_private_candidate_preflight_without_publishing_boot_gates() {
    use crate::{api::application::manual_candidate_fixture, update::app_stage::AppStage};
    use std::{fs, path::Path};

    let project = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    for side in ["a", "b"] {
        let archive = project.join(format!(
            "build/audit/remediation-2026-10-17/host/boot-script-catalog-candidate-valid-{side}/out/boot-script-catalog-fixture.tar.gz"
        ));
        let mut source = File::open(archive).unwrap();
        assert_eq!(source.metadata().unwrap().len(), 17_977_914);
        let mut bytes = vec![0; 17_977_914];
        source.read_exact(&mut bytes).unwrap();
        assert_eq!(source.read(&mut [0; 1]).unwrap(), 0);
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            "dc3467077ee50e41b1e54a1d59bc3e6361b803d5f3281f3d643dcef1926d7eba"
        );
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("kvmapp")).unwrap();
        fs::write(root.path().join("kvmapp/identity"), b"old app unchanged").unwrap();
        fs::create_dir_all(root.path().join("etc/init.d")).unwrap();
        fs::write(
            root.path().join("etc/init.d/S95nanokvm"),
            b"old gate unchanged",
        )
        .unwrap();
        let candidate =
            manual_candidate_fixture(AppStage::fixture(root.path()).unwrap(), &bytes).unwrap();
        let app = candidate.fixture_root();
        let catalog = inspect(&File::open(app.join("server/NanoKVM-Server")).unwrap()).unwrap();
        for (member, role) in catalog.members().iter().zip(ROLES) {
            let expected =
                fs::read(project.join("kvmapp/system/init.d").join(role.filename())).unwrap();
            assert_eq!(member.size(), expected.len() as u64);
            assert_eq!(
                *member.sha256(),
                <[u8; 32]>::from(Sha256::digest(&expected))
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
        assert_eq!(
            fs::read(root.path().join("etc/init.d/S95nanokvm")).unwrap(),
            b"old gate unchanged"
        );
        assert!(!root.path().join("usr/libexec").exists());
        assert!(!root.path().join("application-slot").exists());
    }
}
