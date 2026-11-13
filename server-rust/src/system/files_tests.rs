use super::*;
use std::os::unix::fs::{MetadataExt, symlink};

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn a_file_is_replaced_whole_with_its_mode_and_no_temporary_left() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings");
    fs::write(&path, b"old").unwrap();
    write_atomic(&path, b"new contents\n", 0o640).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"new contents\n");
    assert_eq!(mode(&path), 0o640);
    assert_eq!(names(dir.path()), ["settings"]);
}

#[test]
fn a_planted_temporary_name_or_link_is_never_written_through() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings");
    let elsewhere = dir.path().join("elsewhere");
    fs::write(&elsewhere, b"unrelated").unwrap();
    // The fixed name RC12 used, and the target itself, as links elsewhere.
    symlink(&elsewhere, dir.path().join(".settings.tmp")).unwrap();
    symlink(&elsewhere, &path).unwrap();
    write_atomic(&path, b"new", 0o644).unwrap();
    assert_eq!(fs::read(&elsewhere).unwrap(), b"unrelated");
    assert!(fs::symlink_metadata(&path).unwrap().is_file());
    assert_eq!(fs::read(&path).unwrap(), b"new");
}

#[test]
fn concurrent_writers_never_share_a_temporary_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings");
    let contents: Vec<Vec<u8>> = (0..8)
        .map(|writer| format!("writer {writer}\n").repeat(4096).into_bytes())
        .collect();
    std::thread::scope(|scope| {
        for content in &contents {
            let path = &path;
            scope.spawn(move || {
                for _ in 0..25 {
                    write_atomic(path, content, 0o644).unwrap();
                }
            });
        }
    });
    let last = fs::read(&path).unwrap();
    assert!(contents.contains(&last));
    assert_eq!(names(dir.path()), ["settings"]);
}

#[test]
fn a_symlink_is_repointed_in_one_rename() {
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("localtime");
    symlink("../usr/share/zoneinfo/UTC", &link).unwrap();
    symlink(dir.path().join("x"), dir.path().join(".localtime.tmp")).unwrap();
    replace_symlink(Path::new("../usr/share/zoneinfo/Europe/Berlin"), &link).unwrap();
    assert_eq!(
        fs::read_link(&link).unwrap(),
        Path::new("../usr/share/zoneinfo/Europe/Berlin")
    );
    assert_eq!(names(dir.path()), [".localtime.tmp", "localtime"]);
}

#[test]
fn removing_a_file_is_durable_and_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings");
    fs::write(&path, b"old").unwrap();
    remove_file(&path).unwrap();
    assert!(!path.exists());
    remove_file(&path).unwrap();
    assert_eq!(names(dir.path()), Vec::<String>::new());
}

#[test]
fn only_the_temporary_names_of_atomic_writes_count_as_abandoned() {
    // The names this module creates, for a plain and a dotted target.
    for target in ["run.sh", "a.b.c.py", "x"] {
        let temp = unique_temp(Path::new("/etc/kvm/scripts").join(target).as_path()).unwrap();
        let name = temp.file_name().unwrap().to_str().unwrap();
        assert!(is_abandoned_temp(name), "{name}");
    }
    // The shape earlier versions wrote: pid and nanoseconds.
    assert!(is_abandoned_temp(".boot.sh.1234.1793036903123456789.tmp"));
    assert!(is_abandoned_temp(".run.sh.77.3.00ff00ff00ff00ff.tmp"));
    for name in [
        // Real scripts and hidden files of a person are state, not leftovers.
        "run.sh",
        ".run.sh",
        ".hidden.tmp",
        ".x.tmp",
        "run.sh.1.2.tmp",
        ".run.sh.1.2.tmp.sh",
        ".run.sh.pid.2.tmp",
        ".run.sh.1.2.00FF00FF00FF00FF.tmp",
        ".run.sh.1.x.00ff00ff00ff00ff.tmp",
        "..1.2.tmp",
        ".1.2.tmp",
        "",
        ".tmp",
    ] {
        assert!(!is_abandoned_temp(name), "{name:?}");
    }
}
