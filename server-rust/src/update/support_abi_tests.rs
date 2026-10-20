use super::*;

#[test]
fn independent_wire_vectors_fix_group_order_endian_and_hash_domain() {
    // Literal wire bytes and independently computed Python hashlib digests:
    // neither the producer nor its hash helper constructs these expectations.
    let mut frame = [0; 128];
    frame[..16].copy_from_slice(b"NKABICAP\x01\x00\x80\x00\x04\x00\x00\x00");
    frame[16..36].copy_from_slice(&[
        0x04, 0x03, 0x02, 0x01, 0x44, 0x33, 0x22, 0x11, 0x02, 0, 0, 0, 0x09, 0, 0, 0, 0xef, 0xbe,
        0xad, 0xde,
    ]);
    frame[96..].copy_from_slice(&[
        0xc2, 0x4f, 0xb1, 0x28, 0x30, 0x92, 0xfb, 0x51, 0x67, 0x60, 0x1b, 0xd1, 0xc6, 0xdc, 0x08,
        0xb8, 0x31, 0x8a, 0xa2, 0xb5, 0x86, 0x8c, 0x1d, 0xcc, 0xfb, 0x00, 0x40, 0x37, 0x4d, 0x6a,
        0xa7, 0x6a,
    ]);
    assert_eq!(
        decode(&frame).unwrap(),
        Declaration {
            role: Role::NativeBroker,
            epochs: Epochs {
                app_storage: 0x0102_0304,
                native_lifecycle: 0x1122_3344,
                helper_framing: 2,
                boot_script_framing: 9,
                support_transition: 0xdead_beef,
            },
        }
    );
    frame[16..36].copy_from_slice(&[1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
    frame[96..].copy_from_slice(&[
        0xdc, 0x2d, 0x9a, 0x9b, 0x0b, 0x22, 0xb1, 0x4c, 0x43, 0xc7, 0x55, 0x3b, 0x64, 0x6c, 0xff,
        0xdb, 0x32, 0xaf, 0xc7, 0xa5, 0x05, 0xf5, 0xd3, 0x51, 0x15, 0xd9, 0xe4, 0x73, 0x28, 0x6d,
        0x5b, 0x33,
    ]);
    assert_eq!(encode(Role::NativeBroker), frame);
}

#[test]
fn current_build_declares_each_exact_role_and_no_transition_support() {
    assert_eq!(CURRENT.support_transition, 0);
    for (index, role) in ROLES.into_iter().enumerate() {
        assert_eq!(role as usize, index + 1);
        let frame = encode(role);
        assert!(checksummed(&frame));
        assert_eq!(
            decode(&frame).unwrap(),
            Declaration {
                role,
                epochs: CURRENT
            }
        );
        for other in ROLES {
            if other != role {
                assert_ne!(frame, encode(other));
                assert_ne!(role.filename(), other.filename());
            }
        }
    }
}

#[test]
fn every_byte_corruption_and_every_truncation_fail_strict_decoding() {
    for role in ROLES {
        let frame = encode(role);
        for offset in 0..BYTES {
            let mut damaged = frame;
            damaged[offset] ^= 1;
            assert!(!checksummed(&damaged));
            assert!(decode(&damaged).is_err(), "{role:?}, {offset}");
        }
        for length in 0..BYTES {
            assert!(!checksummed(&frame[..length]));
            assert!(decode(&frame[..length]).is_err());
        }
        let mut extended = frame.to_vec();
        extended.push(0);
        assert!(!checksummed(&extended));
        assert!(decode(&extended).is_err());
    }
}

#[test]
fn checksummed_unknown_format_length_role_and_reserved_data_are_not_literals() {
    for offset in [8, 9, 10, 11, 12, 13, 15, 36, 95] {
        let mut frame = encode(Role::Backend);
        frame[offset] = if offset == 12 { 7 } else { frame[offset] ^ 1 };
        let digest = hash(&frame[..PREFIX]);
        frame[PREFIX..].copy_from_slice(&digest);
        assert!(checksummed(&frame));
        assert!(decode(&frame).is_err(), "unknown field at {offset}");
    }
}

#[test]
fn unknown_group_epochs_remain_explicit_diagnostics_not_compatibility() {
    for (index, unknown) in [0, 2, u32::MAX].into_iter().enumerate() {
        for group in 0..5 {
            let mut frame = encode(Role::NativeBroker);
            let offset = 16 + group * 4;
            frame[offset..offset + 4].copy_from_slice(&unknown.to_le_bytes());
            let digest = hash(&frame[..PREFIX]);
            frame[PREFIX..].copy_from_slice(&digest);
            let declaration = decode(&frame).unwrap();
            assert_eq!(declaration.role, Role::NativeBroker);
            assert_eq!(encode(Role::NativeBroker)[12], declaration.role as u8);
            if !(group == 4 && index == 0) {
                assert_ne!(declaration.epochs, CURRENT);
            } else {
                assert_eq!(declaration.epochs, CURRENT);
                assert_eq!(declaration.epochs.support_transition, 0);
            }
        }
    }
}
