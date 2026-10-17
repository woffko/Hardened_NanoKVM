use super::*;

const PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/bin/false\noperator:x:1000:1000:Operator:/home/operator:/bin/sh\n";
const GROUP: &str = "root:x:0:\ndaemon:x:1:\nusers:x:1000:operator\nvideo:x:44:operator\n";
const SYNTHETIC_HASH: &str = "$5$synthetic$...........................................";
const SHADOW: &str = "root:$5$synthetic$...........................................:20000:0:99999:7:::\ndaemon:*:::::::\noperator:!:::::::\n";
const GSHADOW: &str = "root:!::\ndaemon:!::\nusers:!:operator:operator\nvideo:!::operator\n";
const IMAGE_PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/bin/false\npicoclaw:x:200:200:Service:/var/lib/picoclaw:/bin/false\n";
const IMAGE_GROUP: &str = "root:x:0:\ndaemon:x:1:\nvideo:x:44:picoclaw\npicoclaw:x:200:\n";
const IMAGE_SHADOW: &str = "root:*:::::::\ndaemon:*:::::::\npicoclaw:!:::::::\n";
const IMAGE_GSHADOW: &str = "root:!::\ndaemon:!::\nvideo:!::picoclaw\npicoclaw:!::\n";

struct Fixture {
    passwd: Vec<u8>,
    group: Vec<u8>,
    shadow: Vec<u8>,
    gshadow: Option<Vec<u8>>,
}
impl Fixture {
    fn source() -> Self {
        Self {
            passwd: PASSWD.into(),
            group: GROUP.into(),
            shadow: SHADOW.into(),
            gshadow: None,
        }
    }
    fn image() -> Self {
        Self {
            passwd: IMAGE_PASSWD.into(),
            group: IMAGE_GROUP.into(),
            shadow: IMAGE_SHADOW.into(),
            gshadow: None,
        }
    }
    fn files(&self) -> AccountFiles<'_> {
        AccountFiles {
            passwd: &self.passwd,
            group: &self.group,
            shadow: &self.shadow,
            gshadow: self.gshadow.as_deref(),
        }
    }
}
fn replace(bytes: &mut Vec<u8>, old: &str, new: &str) {
    let text = std::str::from_utf8(bytes).unwrap();
    assert!(text.contains(old));
    *bytes = text.replace(old, new).into_bytes();
}

#[test]
fn no_op_merge_preserves_existing_account_hash_and_file_bytes() {
    let mut source = Fixture::source();
    source.passwd.extend_from_slice(b"# local comment\n");
    source.shadow.extend_from_slice(b"# local comment\n");
    source.group.extend_from_slice(b"# local comment\n");
    let result = merge(&source.files(), &source.files()).unwrap();
    assert_eq!(&*result.passwd, &source.passwd);
    assert_eq!(&*result.shadow, &source.shadow);
    assert_eq!(&*result.group, &source.group);
    assert!(result.gshadow.is_none());
}

#[test]
fn signed_locked_service_is_added_without_losing_user_or_password_state() {
    let source = Fixture::source();
    let image = Fixture::image();
    let result = merge(&source.files(), &image.files()).unwrap();
    assert!(result.passwd.starts_with(PASSWD.as_bytes()));
    assert!(result.shadow.starts_with(SHADOW.as_bytes()));
    assert!(
        result
            .passwd
            .ends_with(b"picoclaw:x:200:200:Service:/var/lib/picoclaw:/bin/false\n")
    );
    assert!(result.shadow.ends_with(b"picoclaw:!:::::::\n"));
    assert!(
        std::str::from_utf8(&result.group)
            .unwrap()
            .contains("video:x:44:operator,picoclaw\n")
    );
    validate(&AccountFiles {
        passwd: &result.passwd,
        group: &result.group,
        shadow: &result.shadow,
        gshadow: None,
    })
    .unwrap();
}

#[test]
fn root_lock_expiry_and_existing_nonroot_hashes_are_not_replaced_by_factory_defaults() {
    let mut source = Fixture::source();
    replace(
        &mut source.shadow,
        SYNTHETIC_HASH,
        "!$6$synthetic$locked-hash",
    );
    replace(
        &mut source.shadow,
        "operator:!:::::::",
        &format!("operator:{SYNTHETIC_HASH}:20000:1:50:3:2:25000:"),
    );
    let image = Fixture::image();
    let result = merge(&source.files(), &image.files()).unwrap();
    assert!(result.shadow.starts_with(&source.shadow));
}

#[test]
fn source_without_final_newline_cannot_concatenate_a_new_account_into_old_row() {
    let mut source = Fixture::source();
    source.passwd.pop();
    source.shadow.pop();
    let result = merge(&source.files(), &Fixture::image().files()).unwrap();
    assert!(
        result
            .passwd
            .windows(b"/bin/sh\npicoclaw:".len())
            .any(|w| w == b"/bin/sh\npicoclaw:")
    );
    assert!(
        result
            .shadow
            .windows(b"operator:!:::::::\npicoclaw:".len())
            .any(|w| w == b"operator:!:::::::\npicoclaw:")
    );
}

#[test]
fn uid_gid_and_common_service_layout_conflicts_require_explicit_migration() {
    for kind in 0..5 {
        let source = Fixture::source();
        let mut image = Fixture::image();
        match kind {
            0 => replace(
                &mut image.passwd,
                "picoclaw:x:200:200",
                "picoclaw:x:1000:200",
            ),
            1 => {
                replace(&mut image.group, "picoclaw:x:200", "picoclaw:x:1000");
                replace(
                    &mut image.passwd,
                    "picoclaw:x:200:200",
                    "picoclaw:x:200:1000",
                );
            }
            2 => replace(&mut image.passwd, "daemon:x:1:1", "daemon:x:11:1"),
            3 => {
                replace(&mut image.group, "daemon:x:1", "daemon:x:11");
                replace(&mut image.passwd, "daemon:x:1:1", "daemon:x:1:11");
            }
            _ => replace(
                &mut image.passwd,
                "/usr/sbin:/bin/false",
                "/var/empty:/bin/false",
            ),
        }
        assert!(
            matches!(
                merge(&source.files(), &image.files()),
                Err(NativeAccountError::Conflict)
            ),
            "conflict case {kind}"
        );
    }
}

#[test]
fn newly_added_accounts_must_be_locked_nonlogin_and_not_primary_root_group() {
    for kind in 0..3 {
        let source = Fixture::source();
        let mut image = Fixture::image();
        match kind {
            0 => replace(
                &mut image.shadow,
                "picoclaw:!:",
                &format!("picoclaw:{SYNTHETIC_HASH}:"),
            ),
            1 => replace(
                &mut image.passwd,
                "/var/lib/picoclaw:/bin/false",
                "/var/lib/picoclaw:/bin/sh",
            ),
            _ => replace(&mut image.passwd, "picoclaw:x:200:200", "picoclaw:x:200:0"),
        }
        assert!(matches!(
            merge(&source.files(), &image.files()),
            Err(NativeAccountError::Conflict)
        ));
    }
}

#[test]
fn existing_service_cannot_silently_keep_login_when_signed_role_requires_locking() {
    let mut source = Fixture::source();
    replace(
        &mut source.shadow,
        "daemon:*:",
        &format!("daemon:{SYNTHETIC_HASH}:"),
    );
    let image = Fixture::image();
    assert!(matches!(
        merge(&source.files(), &image.files()),
        Err(NativeAccountError::Conflict)
    ));
    // An already disabled passwd marker satisfies the requirement without
    // rewriting or deleting the retained shadow hash.
    replace(&mut source.passwd, "daemon:x:", "daemon:!:");
    let merged = merge(&source.files(), &image.files()).unwrap();
    assert!(merged.shadow.starts_with(&source.shadow));
}

#[test]
fn gshadow_presence_matrix_keeps_password_admins_and_members_consistent() {
    for old_has in [false, true] {
        for new_has in [false, true] {
            let mut source = Fixture::source();
            let mut image = Fixture::image();
            source.gshadow = old_has.then(|| GSHADOW.as_bytes().to_vec());
            image.gshadow = new_has.then(|| IMAGE_GSHADOW.as_bytes().to_vec());
            let result = merge(&source.files(), &image.files()).unwrap();
            assert_eq!(result.gshadow.is_some(), old_has || new_has);
            if let Some(gshadow) = &result.gshadow {
                let text = std::str::from_utf8(gshadow).unwrap();
                assert!(text.contains("video:!::operator,picoclaw\n"));
                if old_has {
                    assert!(text.contains("users:!:operator:operator\n"));
                }
            }
            let again = merge(
                &AccountFiles {
                    passwd: &result.passwd,
                    group: &result.group,
                    shadow: &result.shadow,
                    gshadow: result.gshadow.as_deref().map(|v| v.as_slice()),
                },
                &image.files(),
            )
            .unwrap();
            assert_eq!(&*again.passwd, &*result.passwd);
            assert_eq!(&*again.shadow, &*result.shadow);
            assert_eq!(&*again.group, &*result.group);
            assert!(again.gshadow == result.gshadow);
        }
    }
}

#[test]
fn gshadow_member_mismatch_or_new_admin_requirement_never_gets_ignored() {
    let mut source = Fixture::source();
    source.gshadow = Some(GSHADOW.into());
    let mut image = Fixture::image();
    image.gshadow = Some(IMAGE_GSHADOW.into());
    replace(
        image.gshadow.as_mut().unwrap(),
        "video:!::picoclaw",
        "video:!:root:picoclaw",
    );
    assert!(matches!(
        merge(&source.files(), &image.files()),
        Err(NativeAccountError::Conflict)
    ));
    replace(
        source.gshadow.as_mut().unwrap(),
        "video:!::operator",
        "video:!::root",
    );
    assert!(validate(&source.files()).is_err());
}

#[test]
fn malformed_or_inconsistent_native_tables_are_rejected_without_secret_errors() {
    for kind in 0..17 {
        let mut source = Fixture::source();
        match kind {
            0 => source
                .passwd
                .extend_from_slice(b"alias:x:0:0:Alias:/root:/bin/sh\n"),
            1 => source
                .passwd
                .extend_from_slice(b"root:x:2:0:Alias:/root:/bin/sh\n"),
            2 => replace(&mut source.passwd, "root:x:0:0", "root:x:1:0"),
            3 => replace(&mut source.passwd, ":1000:1000:", ":1000:999:"),
            4 => replace(
                &mut source.passwd,
                "root:x:",
                "root:synthetic-secret-marker:",
            ),
            5 => replace(
                &mut source.passwd,
                "root:/root:/bin/sh",
                "root:/root/../root:/bin/sh",
            ),
            6 => replace(
                &mut source.passwd,
                "root:/root:/bin/sh",
                "root:/root:/bin/false",
            ),
            7 => replace(
                &mut source.passwd,
                "root:/root:/bin/sh",
                "root:/home/admin:/bin/sh",
            ),
            8 => source.group.extend_from_slice(b"alias:x:44:\n"),
            9 => replace(
                &mut source.group,
                "video:x:44:operator",
                "video:x:44:missing",
            ),
            10 => replace(
                &mut source.shadow,
                &format!("root:{SYNTHETIC_HASH}:"),
                "root::",
            ),
            11 => replace(
                &mut source.shadow,
                ":20000:0:",
                ":synthetic-secret-marker:0:",
            ),
            12 => source.shadow.extend_from_slice(b"missing:!:::::::\n"),
            13 => source.shadow.push(0),
            14 => source.shadow.push(0xff),
            15 => source.passwd.extend_from_slice(b"+::::::\n"),
            _ => replace(&mut source.passwd, "root:x:0:0", "root:x:4294967295:0"),
        }
        let error = validate(&source.files()).err().unwrap();
        assert!(!format!("{error:?} {error}").contains("synthetic-secret-marker"));
    }
}

#[test]
fn native_table_limits_apply_before_parsing_and_during_merged_output() {
    let mut source = Fixture::source();
    source.passwd = vec![b'a'; MAX_TABLE_BYTES + 1];
    assert!(matches!(
        validate(&source.files()),
        Err(NativeAccountError::Limit)
    ));
    source = Fixture::source();
    source.passwd.extend_from_slice(&vec![b'#'; MAX_LINE + 1]);
    assert!(matches!(
        validate(&source.files()),
        Err(NativeAccountError::Limit)
    ));
    source = Fixture::source();
    source.passwd.extend_from_slice(&b"#\n".repeat(MAX_ROWS));
    assert!(matches!(
        validate(&source.files()),
        Err(NativeAccountError::Limit)
    ));
    source = Fixture::source();
    while source.passwd.len() < MAX_TABLE_BYTES {
        let remaining = MAX_TABLE_BYTES - source.passwd.len();
        let length = remaining.min(MAX_LINE);
        if length > 1 {
            source.passwd.extend_from_slice(&vec![b'#'; length - 1]);
        }
        source.passwd.push(b'\n');
    }
    validate(&source.files()).unwrap();
    assert!(matches!(
        merge(&source.files(), &Fixture::image().files()),
        Err(NativeAccountError::Limit)
    ));
}

#[test]
fn malformed_or_unsupported_modular_password_hashes_are_not_native_ready() {
    for hash in [
        "$unknown$salt$checksum",
        "$y$params$salt$checksum",
        "$6$short$hash",
        "$5$rounds=10000000$salt$...........................................",
    ] {
        let mut source = Fixture::source();
        replace(&mut source.shadow, SYNTHETIC_HASH, hash);
        assert!(
            validate(&source.files()).is_err(),
            "unsupported hash format was accepted"
        );
    }
}
