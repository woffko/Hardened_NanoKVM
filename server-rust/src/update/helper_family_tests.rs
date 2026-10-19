use super::*;
use std::{
    io::{Seek, SeekFrom, Write},
    os::unix::fs::FileExt,
};

fn image(tag: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 120];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&243_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(tag);
    bytes
}

fn frame(role: Role, image: &[u8]) -> Vec<u8> {
    let mut bytes = role.magic().to_vec();
    bytes.extend_from_slice(&(image.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&Sha256::digest(image));
    bytes.extend_from_slice(image);
    bytes
}

fn frames() -> [Vec<u8>; 5] {
    ROLES.map(|role| frame(role, &image(role.filename().as_bytes())))
}

// Shared archive data only; these minimal non-runnable RV64 ELF fixtures still
// traverse the real production binding/layout checks. No validation bypass.
pub(crate) fn candidate_files_fixture() -> Vec<(String, Vec<u8>)> {
    let backend = frames().concat();
    let mut files = vec![
        ("kvmapp/server/NanoKVM-Server".into(), backend.clone()),
        ("kvmapp/backends/NanoKVM-Server.rust".into(), backend),
    ];
    for role in ROLES {
        files.push((
            format!("kvmapp/system/bin/{}", role.filename()),
            image(role.filename().as_bytes()),
        ));
    }
    files
}

fn inspect_bytes(bytes: &[u8]) -> io::Result<Family> {
    inspect_with(bytes.len() as u64, |out, offset| {
        let start = offset as usize;
        let source = bytes
            .get(start..start + out.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        out.copy_from_slice(source);
        Ok(())
    })
}

#[test]
fn complete_exact_family_has_closed_order_sizes_and_digests_without_authentication_claim() {
    // Even a byte string can carry consistent bindings. This API deliberately
    // does not authenticate an outer backend, archive, signature or pathname.
    let mut backend = b"synthetic, NOT authenticated executable bytes".to_vec();
    for bytes in frames().into_iter().rev() {
        backend.extend_from_slice(&bytes);
    }
    let family = inspect_bytes(&backend).unwrap();
    for (member, role) in family.members().iter().zip(ROLES) {
        let expected = image(role.filename().as_bytes());
        assert_eq!(member.role(), role);
        assert_eq!(member.size(), expected.len() as u64);
        assert_eq!(
            *member.sha256(),
            <[u8; 32]>::from(Sha256::digest(&expected))
        );
        assert_eq!(
            &backend[member.start as usize..member.start as usize + 8],
            role.magic()
        );
    }
}

#[test]
fn every_role_is_required_and_ssh_cannot_substitute() {
    for (missing, role) in ROLES.into_iter().enumerate() {
        let mut bytes = Vec::new();
        for (index, member) in frames().iter().enumerate() {
            if index != missing {
                bytes.extend_from_slice(member);
            }
        }
        let mut substitute = frame(role, &image(b"substitute"));
        substitute[..8].copy_from_slice(restore_binding::MAGIC);
        bytes.extend_from_slice(&substitute);
        assert!(inspect_bytes(&bytes).is_err(), "missing {:?}", role);
    }
}

#[test]
fn duplicate_valid_members_are_ambiguous_even_if_bytes_are_identical() {
    for role in ROLES {
        for different in [false, true] {
            let mut bytes = frames().concat();
            let tag = if different {
                b"other".as_slice()
            } else {
                role.filename().as_bytes()
            };
            bytes.extend_from_slice(&frame(role, &image(tag)));
            assert!(
                inspect_bytes(&bytes).is_err(),
                "{role:?}, different={different}"
            );
        }
    }
}

#[test]
fn corrupt_and_truncated_members_never_complete_a_family() {
    for damaged in 0..ROLES.len() {
        for position in [8, 16, restore_binding::HEADER, frames()[damaged].len() - 1] {
            let mut members = frames();
            members[damaged][position] ^= 1;
            assert!(inspect_bytes(&members.concat()).is_err());
        }
        let mut members = frames();
        members[damaged].pop();
        assert!(inspect_bytes(&members.concat()).is_err());
    }
    let bytes = frames().concat();
    for removed in 1..=restore_binding::HEADER + 1 {
        assert!(inspect_bytes(&bytes[..bytes.len() - removed]).is_err());
    }
}

#[test]
fn nonbinding_literals_do_not_hide_a_later_valid_family() {
    let mut bytes = Vec::new();
    for role in ROLES {
        bytes.extend_from_slice(role.magic());
        bytes.extend_from_slice(&[0; 40]);
        let mut corrupt = frame(role, &image(b"corrupt"));
        corrupt[16] ^= 1;
        bytes.extend_from_slice(&corrupt);
        let mut wrong_elf = image(b"not RV64");
        wrong_elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes.extend_from_slice(&frame(role, &wrong_elf));
    }
    bytes.extend_from_slice(&frames().concat());
    inspect_bytes(&bytes).unwrap();
}

#[test]
fn marker_at_each_scan_boundary_offset_is_found_once() {
    let expected = inspect_bytes(&frames().concat()).unwrap();
    for role in ROLES {
        for boundary in CHUNK - 47..=CHUNK + 8 {
            let mut bytes = vec![0; boundary];
            bytes.extend_from_slice(&frame(role, &image(role.filename().as_bytes())));
            for other in ROLES {
                if other != role {
                    bytes.extend_from_slice(&frame(other, &image(other.filename().as_bytes())));
                }
            }
            let actual = inspect_bytes(&bytes).unwrap();
            for (a, b) in actual.members().iter().zip(expected.members()) {
                assert_eq!(
                    (a.role(), a.size(), a.sha256()),
                    (b.role(), b.size(), b.sha256())
                );
            }
        }
    }
}

#[test]
fn image_larger_than_scan_chunk_and_tail_marker_are_checked() {
    let mut large = image(b"large");
    large.resize(CHUNK * 2 + 31, 0x55);
    let mut bytes = frame(Role::AppRecovery, &large);
    for role in &ROLES[1..] {
        bytes.extend_from_slice(&frame(*role, &image(role.filename().as_bytes())));
    }
    // A complete literal at EOF lacks an envelope; it is counted but cannot
    // replace the existing valid member or cause an out-of-file read.
    bytes.extend_from_slice(Role::NativeOwner.magic());
    let family = inspect_bytes(&bytes).unwrap();
    assert_eq!(family.members()[0].size(), large.len() as u64);
    bytes[restore_binding::HEADER + CHUNK + 5] ^= 1;
    assert!(inspect_bytes(&bytes).is_err());
}

#[test]
fn marker_cap_includes_invalid_literals_and_lookahead_does_not_double_count() {
    for role in ROLES {
        let mut bytes = frames().concat();
        for _ in 1..MAX_MARKERS {
            bytes.extend_from_slice(role.magic());
            bytes.extend_from_slice(&[0; 40]);
        }
        inspect_bytes(&bytes).unwrap();
        bytes.extend_from_slice(role.magic());
        assert!(inspect_bytes(&bytes).is_err());
    }
}

#[test]
fn cross_role_nested_frames_are_not_an_independent_helper_family() {
    let owner = frame(Role::NativeOwner, &image(b"nested owner"));
    let mut app = image(b"outer app");
    app.extend_from_slice(&owner);
    let mut bytes = frame(Role::AppRecovery, &app);
    for role in &ROLES[2..] {
        bytes.extend_from_slice(&frame(*role, &image(role.filename().as_bytes())));
    }
    assert!(inspect_bytes(&bytes).is_err());
}

#[test]
fn invalid_elf_architecture_or_dynamic_segments_are_rejected_with_correct_hashes() {
    for role in ROLES {
        for fault in 0..8 {
            let mut elf = image(b"invalid ELF");
            match fault {
                0 => elf[0] = 0,
                1 => elf[18..20].copy_from_slice(&62_u16.to_le_bytes()),
                2 => elf[64..68].copy_from_slice(&2_u32.to_le_bytes()),
                3 => elf[64..68].copy_from_slice(&3_u32.to_le_bytes()),
                4 => elf[56..58].copy_from_slice(&0_u16.to_le_bytes()),
                5 => elf[32..40].copy_from_slice(&u64::MAX.to_le_bytes()),
                6 => elf[96..104].copy_from_slice(&u64::MAX.to_le_bytes()),
                _ => elf[112..120].copy_from_slice(&3_u64.to_le_bytes()),
            }
            let mut bytes = Vec::new();
            for other in ROLES {
                bytes.extend_from_slice(&frame(
                    other,
                    &if other == role {
                        elf.clone()
                    } else {
                        image(other.filename().as_bytes())
                    },
                ));
            }
            assert!(inspect_bytes(&bytes).is_err(), "{role:?}, fault={fault}");
        }
    }
}

#[test]
fn source_io_errors_at_scan_header_hash_and_elf_reads_remain_errors() {
    let bytes = frames().concat();
    let mut reads = Vec::new();
    inspect_with(bytes.len() as u64, |out, offset| {
        reads.push((offset, out.len()));
        out.copy_from_slice(&bytes[offset as usize..offset as usize + out.len()]);
        Ok(())
    })
    .unwrap();
    assert!(reads.iter().any(|(_, size)| *size == 48));
    assert!(reads.iter().any(|(_, size)| *size == 56));
    for failed in 0..reads.len() {
        let mut call = 0;
        let error = inspect_with(bytes.len() as u64, |out, offset| {
            let current = call;
            call += 1;
            if current == failed {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            out.copy_from_slice(&bytes[offset as usize..offset as usize + out.len()]);
            Ok(())
        })
        .unwrap_err();
        assert_eq!(
            error.kind(),
            io::ErrorKind::PermissionDenied,
            "read {failed}"
        );
        assert_eq!(call, failed + 1);
    }
}

#[test]
fn source_change_between_scan_and_header_is_not_ignored() {
    let bytes = frames().concat();
    let error = inspect_with(bytes.len() as u64, |out, offset| {
        out.copy_from_slice(&bytes[offset as usize..offset as usize + out.len()]);
        if out.len() == restore_binding::HEADER {
            out[0] ^= 1;
        }
        Ok(())
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn backend_size_is_bounded_before_any_read_and_large_input_uses_only_fixed_reads() {
    for size in [0, 63, MAX_BACKEND_BYTES + 1, u64::MAX] {
        let error = inspect_with(size, |_, _| panic!("must not read invalid size")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
    let mut reads = 0;
    let error = inspect_with(MAX_BACKEND_BYTES, |out, offset| {
        reads += 1;
        assert!(out.len() <= CHUNK + 7);
        assert!(offset + out.len() as u64 <= MAX_BACKEND_BYTES);
        out.fill(0);
        Ok(())
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(reads, MAX_BACKEND_BYTES as usize / CHUNK);
}

#[test]
fn per_role_size_and_accumulated_hash_work_are_checked_before_body_reads() {
    for role in ROLES {
        for size in [0, 63, role.maximum() + 1, u64::MAX] {
            let mut header = [0; restore_binding::HEADER];
            header[..8].copy_from_slice(role.magic());
            header[8..16].copy_from_slice(&size.to_le_bytes());
            let mut remaining = MAX_HASH_BYTES;
            let mut buffer = [0; CHUNK];
            let mut reads = 0;
            let result = inspect_member(
                role,
                0,
                MAX_BACKEND_BYTES,
                &mut |out, offset| {
                    reads += 1;
                    assert_eq!((offset, out.len()), (0, restore_binding::HEADER));
                    out.copy_from_slice(&header);
                    Ok(())
                },
                &mut buffer,
                &mut remaining,
            )
            .unwrap();
            assert!(result.is_none());
            assert_eq!(reads, 1);
            assert_eq!(remaining, MAX_HASH_BYTES);
        }
    }
    let role = Role::AppRecovery;
    let bytes = frame(role, &image(b"hash work"));
    let size = bytes.len() as u64 - restore_binding::HEADER as u64;
    let mut remaining = 2 * size;
    let mut buffer = [0; CHUNK];
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
            &mut remaining,
        );
        assert_eq!(result.is_ok(), expected_ok);
        if !expected_ok {
            assert_eq!(reads, 1, "budget failure must precede body/ELF reads");
        }
    }
    assert_eq!(remaining, 0);
}

#[test]
fn inspect_pins_no_path_and_does_not_change_a_shared_file_cursor() {
    let mut file = tempfile::tempfile().unwrap();
    let bytes = frames().concat();
    file.write_all(&bytes).unwrap();
    file.seek(SeekFrom::Start(37)).unwrap();
    let alias = file.try_clone().unwrap();
    assert_eq!(inspect(&file).unwrap(), inspect_bytes(&bytes).unwrap());
    assert_eq!(file.stream_position().unwrap(), 37);
    let mut alias = alias;
    assert_eq!(alias.stream_position().unwrap(), 37);
    let mut check = vec![0; bytes.len()];
    file.read_exact_at(&mut check, 0).unwrap();
    assert_eq!(check, bytes);
    assert!(inspect(&File::open(tempfile::tempdir().unwrap().path()).unwrap()).is_err());
}

fn candidate_tree(root: &Path) {
    use std::fs;
    for (name, bytes) in candidate_files_fixture() {
        let path = root.join(name.strip_prefix("kvmapp/").unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
}

#[test]
fn private_candidate_requires_both_backends_and_all_five_exact_bundled_helpers() {
    use std::fs;
    for (name, _) in candidate_files_fixture() {
        let name = name.strip_prefix("kvmapp/").unwrap();
        for fault in [
            "missing", "corrupt", "longer", "symlink", "hardlink", "fifo", "mode",
        ] {
            let root = tempfile::tempdir().unwrap();
            candidate_tree(root.path());
            check_candidate(root.path()).unwrap();
            let path = root.path().join(name);
            match fault {
                "missing" => fs::remove_file(&path).unwrap(),
                "corrupt" => {
                    let mut bytes = fs::read(&path).unwrap();
                    *bytes.last_mut().unwrap() ^= 1;
                    fs::write(&path, bytes).unwrap();
                }
                "longer" => {
                    let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
                    file.set_len(file.metadata().unwrap().len() + 1).unwrap();
                }
                "symlink" => {
                    fs::rename(&path, root.path().join("outside")).unwrap();
                    std::os::unix::fs::symlink(root.path().join("outside"), &path).unwrap();
                }
                "hardlink" => fs::hard_link(&path, root.path().join("alias")).unwrap(),
                "fifo" => {
                    fs::remove_file(&path).unwrap();
                    rustix::fs::mknodat(
                        rustix::fs::CWD,
                        &path,
                        rustix::fs::FileType::Fifo,
                        rustix::fs::Mode::from_raw_mode(0o600),
                        0,
                    )
                    .unwrap();
                }
                _ => {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o622)).unwrap();
                }
            }
            assert!(check_candidate(root.path()).is_err(), "{name}, {fault}");
            // A failed prerequisite never repairs/installs candidate files.
            if fault == "missing" {
                assert!(!path.exists());
            }
            if fault == "mode" {
                assert_eq!(path.metadata().unwrap().mode() & 0o7777, 0o622);
            }
        }
    }
}

#[test]
fn private_candidate_rejects_unsafe_or_aliased_parent_directories_without_repair() {
    use std::{fs, os::unix::fs::PermissionsExt};
    for name in ["", "server", "backends", "system", "system/bin"] {
        let root = tempfile::tempdir().unwrap();
        candidate_tree(root.path());
        let path = root.path().join(name);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(check_candidate(root.path()).is_err(), "{name}");
        assert_eq!(path.metadata().unwrap().mode() & 0o7777, 0o777);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        check_candidate(root.path()).unwrap();
        if !name.is_empty() {
            let parked = root.path().join("outside");
            fs::rename(&path, &parked).unwrap();
            std::os::unix::fs::symlink(&parked, &path).unwrap();
            assert!(check_candidate(root.path()).is_err(), "aliased {name}");
            assert!(path.symlink_metadata().unwrap().is_symlink());
        }
    }
}

#[test]
fn opaque_candidate_factory_rejects_inconsistent_family_before_receipt_or_live_mutation() {
    use crate::{api::application::manual_candidate_fixture, update::app_stage::AppStage};
    use std::fs;
    for role in ROLES {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("kvmapp")).unwrap();
        fs::write(root.path().join("kvmapp/identity"), b"old app untouched").unwrap();
        let mut files = candidate_files_fixture();
        files.push(("kvmapp/version".into(), b"2.0.43\n".to_vec()));
        files.push((
            "kvmapp/system/init.d/S95nanokvm".into(),
            b"synthetic init".to_vec(),
        ));
        let name = format!("kvmapp/system/bin/{}", role.filename());
        let (_, bytes) = files.iter_mut().find(|(path, _)| path == &name).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);
        for (name, bytes) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, name, bytes.as_slice())
                .unwrap();
        }
        let bytes = builder.into_inner().unwrap().finish().unwrap();
        let error = manual_candidate_fixture(AppStage::fixture(root.path()).unwrap(), &bytes)
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            "bad request: app candidate helper family is incomplete or inconsistent"
        );
        assert_eq!(
            fs::read(root.path().join("kvmapp/identity")).unwrap(),
            b"old app untouched"
        );
        assert!(!root.path().join("application-slot").exists());
        assert!(!root.path().join("usr").exists());
    }
}

#[test]
fn candidate_comparison_and_helper_digest_cover_data_after_the_first_chunk() {
    use std::fs;
    let root = tempfile::tempdir().unwrap();
    candidate_tree(root.path());
    let mut app = image(b"large bundled app helper");
    app.resize(2 * CHUNK + 9, 0x55);
    let mut backend = frame(Role::AppRecovery, &app);
    for role in &ROLES[1..] {
        backend.extend_from_slice(&frame(*role, &image(role.filename().as_bytes())));
    }
    let live = root.path().join("server/NanoKVM-Server");
    let backup = root.path().join("backends/NanoKVM-Server.rust");
    let helper = root.path().join("system/bin/nanokvm-app-recovery");
    fs::write(&live, &backend).unwrap();
    fs::write(&backup, &backend).unwrap();
    fs::write(&helper, &app).unwrap();
    check_candidate(root.path()).unwrap();
    let original = backend[CHUNK + 3];
    backend[CHUNK + 3] ^= 1;
    fs::write(&backup, &backend).unwrap();
    assert!(check_candidate(root.path()).is_err());
    backend[CHUNK + 3] = original;
    fs::write(&backup, &backend).unwrap();
    check_candidate(root.path()).unwrap();
    app[2 * CHUNK + 8] ^= 1;
    fs::write(&helper, &app).unwrap();
    assert!(check_candidate(root.path()).is_err());
}
