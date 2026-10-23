use super::*;

const PASSWD: &[u8] = b"root:x:0:0:root:/root:/bin/sh\nsshd:x:999:999:sshd:/var/empty:/bin/false\n";
const GROUP: &[u8] = b"root:x:0:\nsshd:x:999:\n";
const SHADOW: &[u8] = b"root:!:::::::\nsshd:!:::::::\n";
const GSHADOW: &[u8] = b"root:!::\nsshd:!::\n";

fn files(gshadow: Option<&'static [u8]>) -> AccountFiles<'static> {
    AccountFiles {
        passwd: PASSWD,
        group: GROUP,
        shadow: SHADOW,
        gshadow,
    }
}

#[test]
fn tables_round_trip_with_and_without_gshadow() {
    for gshadow in [Some(GSHADOW), None] {
        let encoded = encode(&files(gshadow)).unwrap();
        let decoded = decode(&encoded).unwrap();
        let tables = decoded.as_files();
        assert_eq!(tables.passwd, PASSWD);
        assert_eq!(tables.group, GROUP);
        assert_eq!(tables.shadow, SHADOW);
        assert_eq!(tables.gshadow, gshadow);
    }
}

#[test]
fn truncated_extended_or_reframed_input_is_refused() {
    let encoded = encode(&files(Some(GSHADOW))).unwrap();
    for length in 0..encoded.len() {
        assert!(
            decode(&encoded[..length]).is_err(),
            "prefix {length} accepted"
        );
    }
    let mut extended = encoded.to_vec();
    extended.push(b'\n');
    assert!(decode(&extended).is_err());
    let mut magic = encoded.to_vec();
    magic[7] ^= 1;
    assert!(decode(&magic).is_err());
    // Only gshadow may be absent.
    for index in 0..3 {
        let mut absent = encoded.to_vec();
        absent[MAGIC.len() + 4 * index..MAGIC.len() + 4 * index + 4]
            .copy_from_slice(&ABSENT.to_le_bytes());
        assert!(decode(&absent).is_err(), "table {index} absent");
    }
    // The lengths alone place the boundaries: one inside a passwd line keeps
    // the total, and validation refuses both cut tables.
    let mut moved = encoded.to_vec();
    let passwd = u32::from_le_bytes(moved[8..12].try_into().unwrap());
    let group = u32::from_le_bytes(moved[12..16].try_into().unwrap());
    moved[8..12].copy_from_slice(&(passwd - 5).to_le_bytes());
    moved[12..16].copy_from_slice(&(group + 5).to_le_bytes());
    assert!(decode(&moved).is_err());
}

#[test]
fn oversized_or_invalid_tables_are_refused_both_ways() {
    let mut header = MAGIC.to_vec();
    for length in [MAX_TABLE_BYTES as u32 + 1, 0, 0, ABSENT] {
        header.extend_from_slice(&length.to_le_bytes());
    }
    assert!(decode(&header).is_err());
    assert!(decode(&vec![0; MAX_ENCODED + 1]).is_err());
    let invalid = AccountFiles {
        passwd: b"root:x:0:0:root:/root\n",
        group: GROUP,
        shadow: SHADOW,
        gshadow: None,
    };
    assert!(encode(&invalid).is_err());
    let mut forged = MAGIC.to_vec();
    for table in [invalid.passwd, GROUP, SHADOW] {
        forged.extend_from_slice(&(table.len() as u32).to_le_bytes());
    }
    forged.extend_from_slice(&ABSENT.to_le_bytes());
    for table in [invalid.passwd, GROUP, SHADOW] {
        forged.extend_from_slice(table);
    }
    assert!(
        decode(&forged).is_err(),
        "a table that fails validation was decoded"
    );
}
