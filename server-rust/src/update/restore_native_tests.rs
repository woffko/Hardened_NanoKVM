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
fn a_clash_with_an_account_people_use_requires_explicit_migration() {
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
            2 => image
                .passwd
                .extend_from_slice(b"operator:x:1001:1000:Service:/var/empty:/bin/false\n"),
            3 => {
                image.group.extend_from_slice(b"users:x:1001:\n");
                image
                    .passwd
                    .extend_from_slice(b"operator:x:1000:1001:Operator:/home/operator:/bin/sh\n");
            }
            _ => image
                .passwd
                .extend_from_slice(b"operator:x:1000:1000:Other:/var/empty:/bin/false\n"),
        }
        if kind >= 2 {
            image.shadow.extend_from_slice(b"operator:!:::::::\n");
        }
        if kind == 2 || kind == 4 {
            image.group.extend_from_slice(b"users:x:1000:\n");
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

const COMPACT_PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\navahi:x:100:101:avahi:/:/bin/false\nsshd:x:101:102:SSH:/var/empty:/bin/false\n";
const COMPACT_GROUP: &str =
    "root:x:0:\navahi:x:101:\nsshd:x:102:\ninput:x:103:\nkvm:x:104:\nsgx:x:105:\n";
const COMPACT_SHADOW: &str = "root:*:::::::\navahi:*:::::::\nsshd:*:::::::\n";
const EXPANDED_PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\navahi:x:100:101:avahi:/:/bin/false\nnamed:x:101:102:BIND:/etc/bind:/bin/false\ndbus:x:102:103:DBus:/run/dbus:/bin/false\nsshd:x:103:104:SSH:/var/empty:/bin/false\n";
const EXPANDED_GROUP: &str = "root:x:0:\navahi:x:101:\nnamed:x:102:\ndbus:x:103:\nsshd:x:104:\ninput:x:105:\nkvm:x:106:\nsgx:x:107:\n";
const EXPANDED_SHADOW: &str = "root:$5$synthetic$...........................................:20000:0:99999:7:::\navahi:*:::::::\nnamed:*:::::::\ndbus:*:::::::\nsshd:*:::::::\n";

fn compact() -> Fixture {
    Fixture {
        passwd: COMPACT_PASSWD.into(),
        group: COMPACT_GROUP.into(),
        shadow: COMPACT_SHADOW.into(),
        gshadow: None,
    }
}
fn expanded() -> Fixture {
    Fixture {
        passwd: EXPANDED_PASSWD.into(),
        group: EXPANDED_GROUP.into(),
        shadow: EXPANDED_SHADOW.into(),
        gshadow: None,
    }
}
fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap()
}

#[test]
fn a_device_of_either_layout_takes_the_service_numbers_of_the_image() {
    let result = merge(&expanded().files(), &compact().files()).unwrap();
    let passwd = text(&result.passwd);
    assert!(passwd.contains("sshd:x:101:102:SSH:/var/empty:/bin/false\n"));
    assert!(!passwd.contains("named:") && !passwd.contains("dbus:"));
    let group = text(&result.group);
    for row in [
        "sshd:x:102:\n",
        "input:x:103:\n",
        "kvm:x:104:\n",
        "sgx:x:105:\n",
    ] {
        assert!(group.contains(row), "{row}");
    }
    assert!(!group.contains("named:") && !group.contains("dbus:"));
    let shadow = text(&result.shadow);
    assert!(shadow.contains(SYNTHETIC_HASH), "root keeps its hash");
    assert!(!shadow.contains("named:") && !shadow.contains("dbus:"));

    let result = merge(&compact().files(), &expanded().files()).unwrap();
    let passwd = text(&result.passwd);
    assert!(passwd.contains("sshd:x:103:104:"));
    assert!(passwd.contains("named:x:101:102:") && passwd.contains("dbus:x:102:103:"));
    assert!(text(&result.group).contains("input:x:105:\n"));
}

#[test]
fn the_merged_tables_satisfy_the_check_of_early_boot() {
    for (device, image) in [
        (expanded(), compact()),
        (compact(), expanded()),
        (compact(), compact()),
    ] {
        let merged = merge(&device.files(), &image.files()).unwrap();
        let files = AccountFiles {
            passwd: &merged.passwd,
            group: &merged.group,
            shadow: &merged.shadow,
            gshadow: merged.gshadow.as_deref().map(|v| v.as_slice()),
        };
        check_for_image(&files, &image.files()).unwrap();
    }
}

#[test]
fn a_device_already_on_the_image_layout_keeps_its_exact_bytes() {
    let mut device = compact();
    replace(
        &mut device.shadow,
        "root:*:",
        &format!("root:{SYNTHETIC_HASH}:"),
    );
    device.passwd.extend_from_slice(b"# local comment\n");
    device.group.extend_from_slice(b"# local comment\n");
    let result = merge(&device.files(), &compact().files()).unwrap();
    assert_eq!(&*result.passwd, &device.passwd);
    assert_eq!(&*result.group, &device.group);
    assert_eq!(&*result.shadow, &device.shadow);
}

#[test]
fn accounts_people_use_stay_and_a_clash_refuses() {
    // An ordinary account elsewhere stays, with its groups.
    let mut device = expanded();
    device
        .passwd
        .extend_from_slice(b"alice:x:1000:1000:Alice:/home/alice:/bin/sh\n");
    device.group.extend_from_slice(b"alice:x:1000:\n");
    device.shadow.extend_from_slice(b"alice:!:::::::\n");
    let result = merge(&device.files(), &compact().files()).unwrap();
    assert!(text(&result.passwd).contains("alice:x:1000:1000:Alice:/home/alice:/bin/sh\n"));
    assert!(text(&result.group).contains("alice:x:1000:\n"));

    // An account with a login shell on a number the image needs.
    let mut device = compact();
    replace(
        &mut device.passwd,
        "avahi:x:100:101:avahi:/:/bin/false",
        "alice:x:100:101:Alice:/home/alice:/bin/sh",
    );
    replace(&mut device.shadow, "avahi:*:", "alice:!:");
    assert!(matches!(
        merge(&device.files(), &compact().files()),
        Err(NativeAccountError::Conflict)
    ));

    // sshd with a shell is not a service account here, whatever its name says.
    let mut device = expanded();
    replace(
        &mut device.passwd,
        "sshd:x:103:104:SSH:/var/empty:/bin/false",
        "sshd:x:103:104:SSH:/var/empty:/bin/sh",
    );
    assert!(matches!(
        merge(&device.files(), &compact().files()),
        Err(NativeAccountError::Conflict)
    ));

    // A group with a person in it keeps its number, so a change refuses.
    let mut device = expanded();
    device
        .passwd
        .extend_from_slice(b"alice:x:1000:1000:Alice:/home/alice:/bin/sh\n");
    device.group.extend_from_slice(b"alice:x:1000:\n");
    device.shadow.extend_from_slice(b"alice:!:::::::\n");
    replace(&mut device.group, "input:x:105:", "input:x:105:alice");
    assert!(matches!(
        merge(&device.files(), &compact().files()),
        Err(NativeAccountError::Conflict)
    ));
}

#[test]
fn a_service_with_a_password_is_kept_out_of_the_replacement() {
    let mut device = expanded();
    replace(
        &mut device.shadow,
        "sshd:*:",
        &format!("sshd:{SYNTHETIC_HASH}:"),
    );
    assert!(matches!(
        merge(&device.files(), &compact().files()),
        Err(NativeAccountError::Conflict)
    ));
}

#[test]
fn departing_services_leave_every_group_and_gshadow_row_consistent() {
    let mut device = expanded();
    device.group.extend_from_slice(b"video:x:44:named,root\n");
    device.gshadow = Some(
        "root:!::\navahi:!::\nnamed:!::\ndbus:!::\nsshd:!::\ninput:!::\nkvm:!::\nsgx:!::\nvideo:!:named:named,root\n"
            .into(),
    );
    let result = merge(&device.files(), &compact().files()).unwrap();
    assert!(text(&result.group).contains("video:x:44:root\n"));
    let gshadow = text(result.gshadow.as_deref().unwrap());
    assert!(gshadow.contains("video:!::root\n"));
    assert!(!gshadow.contains("named"));
    assert!(gshadow.contains("input:!::\n"));
}

#[test]
fn a_device_service_the_image_does_not_know_is_not_kept() {
    let mut device = compact();
    device
        .passwd
        .extend_from_slice(b"oldsvc:x:300:300:Old:/var/empty:/bin/false\n");
    device.group.extend_from_slice(b"oldsvc:x:300:\n");
    device.shadow.extend_from_slice(b"oldsvc:*:::::::\n");
    let result = merge(&device.files(), &compact().files()).unwrap();
    assert_eq!(text(&result.passwd), COMPACT_PASSWD);
    assert_eq!(text(&result.group), COMPACT_GROUP);
}

#[test]
fn a_service_with_another_home_or_shell_takes_the_row_of_the_image() {
    let mut device = compact();
    replace(
        &mut device.passwd,
        "sshd:x:101:102:SSH:/var/empty:/bin/false",
        "sshd:x:101:102:SSH:/run/sshd:/sbin/nologin",
    );
    let result = merge(&device.files(), &compact().files()).unwrap();
    assert!(text(&result.passwd).contains("sshd:x:101:102:SSH:/var/empty:/bin/false\n"));
    assert!(!text(&result.passwd).contains("/run/sshd"));
}

#[test]
fn an_account_made_on_the_device_stays_whatever_its_shell_and_lock() {
    let mut device = compact();
    device
        .passwd
        .extend_from_slice(b"files:x:1000:1000:Files:/home/files:/bin/false\n");
    device
        .group
        .extend_from_slice(b"files:x:1000:\nshare:x:1001:\n");
    device.shadow.extend_from_slice(b"files:*:::::::\n");
    let result = merge(&device.files(), &compact().files()).unwrap();
    assert!(text(&result.passwd).contains("files:x:1000:1000:Files:/home/files:/bin/false\n"));
    assert!(text(&result.shadow).contains("files:*:::::::\n"));
    assert!(text(&result.group).contains("files:x:1000:\n"));
    assert!(text(&result.group).contains("share:x:1001:\n"));
}
