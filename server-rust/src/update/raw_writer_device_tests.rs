use super::*;

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
