//! Failure-only bounded observations, never checkpoint or recovery authority.
use std::{fs, io::Read, path::Path};

const THREAD_LIMIT: usize = 16;
const FIELD_BYTES: usize = 512;
const OUTPUT_BYTES: usize = 16 * 1024;
const TRUNCATED: &str = "\n[diagnostic output truncated]\n";
const FIELDS: [&str; 4] = ["comm", "wchan", "syscall", "stack"];

pub(super) fn child_threads(pid: u32) -> String {
    // Only the observed Child's fixed proc task directory, never argv, env,
    // descriptors, arbitrary process memory or a caller-selected runtime path.
    capture_at(Path::new(&format!("/proc/{pid}/task")))
}

pub(crate) fn observed_thread(pid: u32, tid: u32) -> String {
    // A worker-reported task identifier is an observation only and may race
    // task exit. No scanning/adoption, signaling, memory, argv, env or fd reads.
    let mut text = String::with_capacity(OUTPUT_BYTES);
    append_task(&mut text, Path::new(&format!("/proc/{pid}/task")), tid);
    text
}

fn field(path: &Path) -> String {
    let mut bytes = Vec::with_capacity(FIELD_BYTES);
    match fs::File::open(path)
        .and_then(|file| file.take(FIELD_BYTES as u64).read_to_end(&mut bytes))
    {
        Ok(_) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(error) => format!("unavailable: {error}"),
    }
}

fn append(text: &mut String, value: &str) -> bool {
    // Reserve the marker inside the hard aggregate bound, including UTF-8 and
    // Debug escaping expansion from individual bounded proc fields.
    let remaining = OUTPUT_BYTES - TRUNCATED.len() - text.len();
    if value.len() <= remaining {
        text.push_str(value);
        return true;
    }
    let mut keep = remaining;
    while !value.is_char_boundary(keep) {
        keep -= 1;
    }
    text.push_str(&value[..keep]);
    text.push_str(TRUNCATED);
    false
}

fn append_task(text: &mut String, directory: &Path, tid: u32) -> bool {
    if !append(text, &format!("tid={tid}\n")) {
        return false;
    }
    for name in FIELDS {
        let value = field(&directory.join(tid.to_string()).join(name));
        if !append(text, &format!("  {name}={value:?}\n")) {
            return false;
        }
    }
    true
}

fn capture_at(directory: &Path) -> String {
    let mut text = String::with_capacity(OUTPUT_BYTES);
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) => {
            append(&mut text, &format!("task list unavailable: {error}"));
            return text;
        }
    };
    let mut tids = Vec::with_capacity(THREAD_LIMIT);
    let mut omitted = false;
    for (index, entry) in entries.take(THREAD_LIMIT + 1).enumerate() {
        if index == THREAD_LIMIT {
            omitted = true;
            break;
        }
        if let Ok(entry) = entry
            && let Some(tid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
        {
            tids.push(tid);
        }
    }
    tids.sort_unstable();
    for tid in tids {
        if !append_task(&mut text, directory, tid) {
            return text;
        }
    }
    if omitted {
        append(&mut text, "[thread limit16: additional tasks omitted]\n");
    }
    text
}

#[test]
fn exact_task_observation_does_not_scan_siblings_and_missing_task_is_not_authority() {
    let root = tempfile::tempdir().unwrap();
    for (tid, name) in [(3, "selected-worker"), (12, "unrelated-worker")] {
        fs::create_dir(root.path().join(tid.to_string())).unwrap();
        fs::write(root.path().join(tid.to_string()).join("comm"), name).unwrap();
    }
    let mut text = String::with_capacity(OUTPUT_BYTES);
    assert!(append_task(&mut text, root.path(), 3));
    assert!(text.contains("tid=3") && text.contains("selected-worker"));
    assert!(!text.contains("tid=12") && !text.contains("unrelated-worker"));
    text.clear();
    assert!(append_task(&mut text, root.path(), 99));
    assert_eq!(text.matches("unavailable:").count(), FIELDS.len());
    assert!(text.len() <= OUTPUT_BYTES);
}

#[test]
fn main_and_worker_observations_are_separate_sorted_and_fields_are_byte_bounded() {
    let root = tempfile::tempdir().unwrap();
    for (tid, name) in [(12, "worker"), (3, "harness")] {
        let task = root.path().join(tid.to_string());
        fs::create_dir(&task).unwrap();
        fs::write(task.join("comm"), name).unwrap();
        for file in ["wchan", "syscall", "stack"] {
            let mut value = vec![b'x'; FIELD_BYTES];
            value.extend_from_slice(b"not retained beyond field limit");
            fs::write(task.join(file), value).unwrap();
        }
    }
    let text = capture_at(root.path());
    assert!(text.find("tid=3\n").unwrap() < text.find("tid=12\n").unwrap());
    assert!(text.contains("comm=\"harness\""));
    assert!(text.contains("comm=\"worker\""));
    assert!(!text.contains("not retained beyond field limit"));
    assert_eq!(text.matches(&"x".repeat(FIELD_BYTES)).count(), 6);
    assert!(text.len() <= OUTPUT_BYTES);
}

#[test]
fn thread_count_and_escaped_binary_output_have_independent_hard_limits() {
    let root = tempfile::tempdir().unwrap();
    for tid in 1..=THREAD_LIMIT + 5 {
        let task = root.path().join(tid.to_string());
        fs::create_dir(&task).unwrap();
        for name in FIELDS {
            fs::write(task.join(name), b"known").unwrap();
        }
    }
    let text = capture_at(root.path());
    assert_eq!(text.matches("tid=").count(), THREAD_LIMIT);
    assert!(text.contains("additional tasks omitted"));
    for tid in 1..=THREAD_LIMIT + 5 {
        for name in FIELDS {
            fs::write(
                root.path().join(tid.to_string()).join(name),
                vec![0; FIELD_BYTES * 2],
            )
            .unwrap();
        }
    }
    let text = capture_at(root.path());
    assert!(text.len() <= OUTPUT_BYTES);
    assert!(text.ends_with(TRUNCATED));
}

#[test]
fn missing_tasks_and_inaccessible_fields_are_observations_not_success_or_panics() {
    let root = tempfile::tempdir().unwrap();
    assert!(capture_at(&root.path().join("absent")).starts_with("task list unavailable:"));
    fs::create_dir(root.path().join("1")).unwrap();
    let text = capture_at(root.path());
    assert_eq!(text.matches("unavailable:").count(), FIELDS.len());
    assert!(text.len() <= OUTPUT_BYTES);
}

#[test]
fn aggregate_truncation_preserves_utf8_and_includes_its_marker_in_the_limit() {
    let mut text = "x".repeat(OUTPUT_BYTES - TRUNCATED.len() - 1);
    assert!(!append(&mut text, "я"));
    assert!(text.ends_with(TRUNCATED));
    assert!(text.len() <= OUTPUT_BYTES);
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("1")).unwrap();
    fs::write(root.path().join("1/comm"), vec![0xff; FIELD_BYTES + 1]).unwrap();
    assert!(capture_at(root.path()).len() <= OUTPUT_BYTES);
}

#[test]
fn actual_proc_capture_names_tasks_without_reading_arguments_or_environment() {
    let text = child_threads(std::process::id());
    assert!(text.contains("tid="), "{text}");
    for name in FIELDS {
        assert!(text.contains(&format!("{name}=")), "{text}");
    }
    assert!(text.len() <= OUTPUT_BYTES);
}

#[test]
fn live_child_capture_distinguishes_blocked_worker_before_owned_teardown() {
    use std::{
        io::BufRead as _,
        process::{Command, Stdio},
        sync::mpsc,
        time::Duration,
    };
    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            // Failure cleanup only; this owned child has no descendants or
            // filesystem/recovery authority. Never signal a looked-up PID.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    std::thread::scope(|scope| {
        // Drop the child BEFORE scope joins a blocked stdout reader on unwind.
        let mut child = OwnedChild(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "update::app_slot::test_diagnostics::diagnostic_child",
                    "--nocapture",
                ])
                .env_clear()
                .env("NANOKVM_APP_DIAGNOSTIC_CHILD", "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let stdout = child.0.stdout.take().unwrap();
        let (send, receive) = mpsc::sync_channel(1);
        scope.spawn(move || {
            // Keep draining after Ready: the child test harness still writes
            // its final result. Closing this pipe would induce BrokenPipe.
            let mut ready = false;
            for line in std::io::BufReader::new(stdout).lines() {
                if !ready && line.is_ok_and(|line| line == "slot-thread-diagnostic-ready") {
                    ready = true;
                    if send.send(true).is_err() {
                        return;
                    }
                }
            }
            if !ready {
                let _ = send.send(false);
            }
        });
        assert_eq!(receive.recv_timeout(Duration::from_secs(6)), Ok(true));
        let text = child_threads(child.0.id());
        assert!(text.contains("slot-diag-block"), "{text}");
        assert!(text.matches("tid=").count() >= 3, "{text}");
        assert!(text.len() <= OUTPUT_BYTES);
        assert!(child.0.try_wait().unwrap().is_none());
        // Capture itself must not Stop/kill/unblock the child. EOF is explicit
        // test cleanup only, AFTER the complete live per-thread observation.
        drop(child.0.stdin.take());
        let status = child.0.wait().unwrap();
        assert!(status.success(), "diagnostic child: {status:?}");
    });
}

#[test]
fn diagnostic_child() {
    use std::io::Write as _;
    use std::sync::mpsc;
    if std::env::var_os("NANOKVM_APP_DIAGNOSTIC_CHILD").as_deref()
        != Some(std::ffi::OsStr::new("1"))
    {
        return;
    }
    let (release, released) = mpsc::channel::<()>();
    let (entered, entering) = mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .name("slot-diag-block".into())
        .spawn(move || {
            entered.send(()).unwrap();
            assert!(released.recv().is_err());
        })
        .unwrap();
    entering.recv().unwrap();
    println!("slot-thread-diagnostic-ready");
    std::io::stdout().flush().unwrap();
    let mut byte = [0];
    assert_eq!(std::io::stdin().read(&mut byte).unwrap(), 0);
    drop(release);
    worker.join().unwrap();
}
