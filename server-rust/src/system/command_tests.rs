use super::*;
use nix::{errno::Errno, sys::wait::waitpid, unistd::Pid};
use std::{fs, os::fd::AsRawFd, path::Path};

const LIMIT: Duration = Duration::from_secs(5);
const SHORT: Duration = Duration::from_millis(300);
const SLEEP: &str = "echo $$ > \"$1\"; exec sleep 30";

#[test]
fn app_slot_gate_uses_only_the_fixed_independent_executable() {
    assert_eq!(
        AllowedCommand::AppSlotGate.program(),
        OsStr::new("/usr/libexec/nanokvm-app-recovery")
    );
    assert_eq!(
        AllowedCommand::PicoclawStop.program(),
        OsStr::new("/bin/busybox")
    );
}

fn shell() -> AllowedCommand {
    AllowedCommand::CustomForTest(PathBuf::from("/bin/sh"))
}

async fn recorded_pid(path: &Path) -> i32 {
    time::timeout(LIMIT, async {
        loop {
            if let Ok(text) = fs::read_to_string(path)
                && let Ok(pid) = text.trim().parse::<i32>()
            {
                return pid;
            }
            time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("fixture did not record its direct PID")
}

fn reaped(pid: i32) {
    assert_eq!(waitpid(Pid::from_raw(pid), None), Err(Errno::ECHILD));
    assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
}

#[tokio::test]
async fn runs_allowlisted_command_with_argv() {
    let out = run_allowed(
        AllowedCommand::CustomForTest(PathBuf::from("/bin/echo")),
        ["hello"],
        LIMIT,
    )
    .await
    .unwrap();
    assert_eq!(out.status, 0);
    assert_eq!(out.stdout, b"hello\n");
}

#[tokio::test]
async fn runs_allowlisted_command_with_stdin() {
    let out = run_allowed_with_stdin(
        AllowedCommand::CustomForTest(PathBuf::from("/bin/cat")),
        std::iter::empty::<&str>(),
        b"synthetic stdin\n",
        LIMIT,
    )
    .await
    .unwrap();
    assert_eq!(out.status, 0);
    assert_eq!(out.stdout, b"synthetic stdin\n");
}

#[tokio::test]
async fn timeout_kills_and_reaps_before_returning() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("pid");
    let result = run_allowed(
        shell(),
        ["-c", SLEEP, "fixture", path.to_str().unwrap()],
        SHORT,
    )
    .await;
    assert!(matches!(result, Err(AppError::Internal(ref text)) if text == "command timed out"));
    reaped(recorded_pid(&path).await);
}

#[tokio::test]
async fn blocked_stdin_is_inside_the_same_deadline_and_reap() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("pid");
    let result = run_allowed_with_stdin(
        shell(),
        ["-c", SLEEP, "fixture", path.to_str().unwrap()],
        &vec![b'x'; 2 * 1024 * 1024],
        SHORT,
    )
    .await;
    assert!(matches!(result, Err(AppError::Internal(ref text)) if text == "command timed out"));
    reaped(recorded_pid(&path).await);
}

#[tokio::test]
async fn zero_exit_without_pipe_eof_is_not_success_or_an_unbounded_wait() {
    // CLOEXEC prevents inheritance across exec, but unrelated parallel forks
    // may temporarily hold a read alias until they reach exec. Check local FD
    // closure immediately and require EPIPE within a separate finite deadline.
    let (reader, writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
    let reader_path = PathBuf::from(format!("/proc/self/fd/{}", reader.as_raw_fd()));
    let reader_identity = fs::read_link(&reader_path).unwrap();
    let alias = writer.try_clone().unwrap();
    let mut command = Command::new("/bin/true");
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().unwrap();
    drop(command);
    let pid = child.id().unwrap() as i32;
    child.stdout = Some(
        tokio::process::ChildStdout::from_std(std::process::ChildStdout::from(reader)).unwrap(),
    );
    let (mut reply, _receive) = oneshot::channel();
    let result = time::timeout(
        LIMIT,
        supervise_capture(&mut child, None, SHORT, &mut reply),
    )
    .await
    .expect("pipe EOF escaped the deadline");
    assert!(matches!(result, Err(AppError::Internal(ref text)) if text == "command timed out"));
    reaped(pid);
    // Capture owns the original reader; it must be closed before the result.
    // Another parallel test may already have reused its descriptor number.
    assert_ne!(fs::read_link(reader_path).ok(), Some(reader_identity));
    time::timeout(LIMIT, async {
        loop {
            match nix::unistd::write(&alias, b"x") {
                Err(Errno::EPIPE) => break,
                Ok(1) => time::sleep(Duration::from_millis(5)).await,
                other => panic!("unexpected pipe probe: {other:?}"),
            }
        }
    })
    .await
    .expect("a leaked reader kept the pipe alive after capture ended");
}

#[tokio::test]
async fn dropped_waiter_signals_the_runtime_owner_to_reap() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("pid");
    let argument = path.clone();
    let request = tokio::spawn(async move {
        run_allowed(
            shell(),
            ["-c", SLEEP, "fixture", argument.to_str().unwrap()],
            Duration::from_secs(30),
        )
        .await
    });
    let pid = recorded_pid(&path).await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    time::timeout(LIMIT, async {
        while PathBuf::from(format!("/proc/{pid}")).exists() {
            time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("cancelled command owner abandoned its child");
    reaped(pid);
}

#[tokio::test]
async fn capture_is_bounded_but_both_streams_are_drained() {
    let out = run_allowed(
        shell(),
        [
            "-c",
            "head -c 300000 /dev/zero; head -c 300000 /dev/zero >&2",
        ],
        LIMIT,
    )
    .await
    .unwrap();
    assert_eq!(out.status, 0);
    assert_eq!(out.stdout.len(), MAX_CAPTURE_BYTES);
    assert_eq!(out.stderr.len(), MAX_CAPTURE_BYTES);
}

#[tokio::test]
async fn early_stdin_failure_keeps_nonzero_status_but_rejects_zero_status() {
    let input = vec![b'x'; 2 * 1024 * 1024];
    let out = run_allowed_with_stdin(
        shell(),
        ["-c", "exec 0<&-; printf 'synthetic failure' >&2; exit 7"],
        &input,
        LIMIT,
    )
    .await
    .unwrap();
    assert_eq!(out.status, 7);
    assert_eq!(out.stderr, b"synthetic failure");
    assert!(
        run_allowed_with_stdin(shell(), ["-c", "exec 0<&-; exit 0"], &input, LIMIT)
            .await
            .is_err()
    );
}

fn login(line: &str) -> Option<String> {
    line.strip_prefix("fixture ").map(str::to_owned)
}

#[tokio::test]
async fn stderr_match_reaps_the_cli_before_returning_the_url() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("pid");
    let value = read_allowed_stderr_until(
        shell(),
        ["-c", "echo $$ > \"$1\"; printf 'ignored\\nfixture https://example.invalid/fixture\\r\\n' >&2; exec sleep 30", "fixture", path.to_str().unwrap()],
        LIMIT,
        login,
    )
    .await
    .unwrap();
    assert_eq!(value.as_deref(), Some("https://example.invalid/fixture"));
    reaped(recorded_pid(&path).await);
}

#[tokio::test]
async fn stderr_eof_does_not_abandon_a_still_running_cli() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("pid");
    let result = read_allowed_stderr_until(
        shell(),
        [
            "-c",
            "echo $$ > \"$1\"; exec 2>&-; exec sleep 30",
            "fixture",
            path.to_str().unwrap(),
        ],
        SHORT,
        login,
    )
    .await;
    assert!(matches!(result, Err(AppError::Internal(ref text)) if text == "command timed out"));
    reaped(recorded_pid(&path).await);
}

#[tokio::test]
async fn dropped_matcher_waiter_also_reaps_its_direct_child() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("pid");
    let argument = path.clone();
    let request = tokio::spawn(async move {
        read_allowed_stderr_until(
            shell(),
            ["-c", SLEEP, "fixture", argument.to_str().unwrap()],
            Duration::from_secs(30),
            login,
        )
        .await
    });
    let pid = recorded_pid(&path).await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    time::timeout(LIMIT, async {
        while PathBuf::from(format!("/proc/{pid}")).exists() {
            time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("cancelled matcher owner abandoned its child");
    reaped(pid);
}

#[tokio::test]
async fn stderr_match_handles_final_line_and_rejects_unbounded_or_invalid_lines() {
    assert_eq!(
        read_allowed_stderr_until(shell(), ["-c", "printf 'fixture final' >&2"], LIMIT, login)
            .await
            .unwrap()
            .as_deref(),
        Some("final")
    );
    assert!(
        read_allowed_stderr_until(
            shell(),
            ["-c", "exec head -c 300000 /dev/zero >&2"],
            LIMIT,
            login,
        )
        .await
        .is_err()
    );
    assert!(
        read_allowed_stderr_until(shell(), ["-c", "printf '\\377\\n' >&2"], LIMIT, login)
            .await
            .is_err()
    );
    assert!(
        read_allowed_stderr_until(shell(), ["-c", "printf 'ignored\\n' >&2"], LIMIT, login)
            .await
            .unwrap()
            .is_none()
    );
}
