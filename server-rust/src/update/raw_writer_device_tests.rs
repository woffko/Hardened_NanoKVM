use super::*;

#[test]
fn diagnostic_is_bounded_and_survives_reopening() {
    let root = tempfile::tempdir().unwrap();
    let mut log = DiagnosticLog::at(root.path(), root.path().metadata().unwrap().dev()).unwrap();
    log.append("raw write: Rootfs written and verified")
        .unwrap();
    let remaining = log.remaining;
    assert!(log.append(&"x".repeat(remaining)).is_err());
    log.append(&"x".repeat(remaining - 1)).unwrap();
    assert!(log.append("").is_err());
    drop(log);
    let bytes = fs::read(root.path().join("latest.log")).unwrap();
    assert_eq!(bytes.len(), DIAGNOSTIC_LIMIT);
    assert!(bytes.starts_with(DIAGNOSTIC_HEADER));
    assert!(
        String::from_utf8(bytes)
            .unwrap()
            .contains("Rootfs written and verified\n")
    );
}

#[test]
fn diagnostic_replacement_does_not_write_through_links() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let victim = root.path().join("victim");
    fs::write(&victim, "preserve this evidence").unwrap();
    let latest = root.path().join("latest.log");
    let device = root.path().metadata().unwrap().dev();
    for hard_link in [false, true] {
        if hard_link {
            fs::hard_link(&victim, &latest).unwrap();
        } else {
            symlink(&victim, &latest).unwrap();
        }
        DiagnosticLog::at(root.path(), device)
            .unwrap()
            .append("new attempt")
            .unwrap();
        assert_eq!(
            fs::read_to_string(&victim).unwrap(),
            "preserve this evidence"
        );
        assert!(
            fs::read_to_string(&latest)
                .unwrap()
                .ends_with("new attempt\n")
        );
        fs::remove_file(&latest).unwrap();
    }
    let alias = root.path().join("alias");
    symlink(root.path(), &alias).unwrap();
    assert!(DiagnosticLog::at(&alias, device).is_err());
    assert!(DiagnosticLog::at(root.path(), device.wrapping_add(1)).is_err());
    assert!(!latest.exists());
}

#[test]
fn diagnostic_failure_preserves_prefix_and_keeps_kmsg_logging() {
    let root = tempfile::tempdir().unwrap();
    DiagnosticLog::at(root.path(), root.path().metadata().unwrap().dev()).unwrap();
    let latest = root.path().join("latest.log");
    let kmsg_path = root.path().join("kmsg");
    let mut system = DeviceSystem {
        kmsg: Some(File::create(&kmsg_path).unwrap()),
        diagnostic: Some(DiagnosticLog {
            file: File::open(&latest).unwrap(), // injected write failure
            remaining: DIAGNOSTIC_LIMIT,
        }),
    };
    system.log("raw write failed: injected failure");
    assert!(system.diagnostic.is_none());
    assert_eq!(fs::read(&latest).unwrap(), DIAGNOSTIC_HEADER);
    let kmsg = fs::read_to_string(&kmsg_path).unwrap();
    assert!(kmsg.contains("persistent diagnostic stopped"));
    assert!(kmsg.contains("raw write failed: injected failure"));
}

fn stat(pid: u32, comm: &str, state: &str, flags: u64) -> String {
    format!("{pid} ({comm}) {state} 1 {pid} {pid} 0 -1 {flags} 120 0 0 0 0 0 0 0 20 0 1 0 100\n")
}

#[test]
fn only_live_user_processes_are_killable() {
    assert!(killable(&stat(42, "sshd", "S", 0x0040_0100)));
    assert!(killable(&stat(43, "NanoKVM-Server", "D", 0x0040_0040)));
    // Kernel threads, zombies and dead entries are never signalled.
    assert!(!killable(&stat(2, "kthreadd", "S", 0x0020_8040)));
    assert!(!killable(&stat(9, "ksoftirqd/0", "S", 0x0420_8040)));
    assert!(!killable(&stat(44, "sh", "Z", 0x0040_0004)));
    assert!(!killable(&stat(45, "sh", "X", 0)));
    // A name with spaces and parentheses shifts no field.
    assert!(killable(&stat(46, "a ) b (c", "S", 0)));
    // Fields inside the name (here a fake kernel-thread flag) are not read.
    assert!(killable(&stat(
        47,
        "x) S 1 2 3 4 5 2097152 (",
        "S",
        0x0040_0100
    )));
    for broken in [
        "",
        "46 (sh S 1",
        "46 (sh) S 1 2 3",
        "46 (sh) S 1 2 3 4 5 flags",
    ] {
        assert!(!killable(broken), "{broken:?}");
    }
}

#[test]
fn the_scan_skips_pid_1_itself_kernel_threads_and_vanished_entries() {
    let proc_root = tempfile::tempdir().unwrap();
    let put = |name: &str, contents: Option<String>| {
        let dir = proc_root.path().join(name);
        fs::create_dir(&dir).unwrap();
        if let Some(contents) = contents {
            fs::write(dir.join("stat"), contents).unwrap();
        }
    };
    put("1", Some(stat(1, "init", "S", 0x0040_0100)));
    put("2", Some(stat(2, "kthreadd", "S", 0x0020_8040)));
    put("300", Some(stat(300, "sshd", "S", 0x0040_0100)));
    put("301", Some(stat(301, "writer", "R", 0x0040_0000)));
    put("302", Some(stat(302, "sh", "Z", 0x0040_0004)));
    put("303", None);
    put("self", None);
    put("sys", None);
    let mut found = victims(proc_root.path(), Pid::from_raw(301).unwrap()).unwrap();
    found.sort_by_key(|pid| pid.as_raw_nonzero());
    assert_eq!(found, [Pid::from_raw(300).unwrap()]);
}

#[test]
fn the_root_is_read_only_only_when_its_last_mount_says_ro() {
    let rw = "/dev/root / ext4 rw,relatime 0 0\nproc /proc proc rw 0 0\n";
    let ro = "/dev/root / ext4 ro,relatime 0 0\n";
    assert!(!root_is_readonly(rw));
    assert!(root_is_readonly(ro));
    assert!(!root_is_readonly(&format!(
        "{ro}overlay / overlay rw 0 0\n"
    )));
    assert!(!root_is_readonly("proc /proc proc ro 0 0\n"));
    assert!(!root_is_readonly(
        "/dev/root / ext4 rw,errors=remount-ro 0 0\n"
    ));
}
