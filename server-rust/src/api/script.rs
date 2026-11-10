use axum::{
    Extension, Json,
    extract::{Multipart, State},
    http::HeaderMap,
    response::IntoResponse,
};
use nix::{
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsStr,
    fs::{self, File},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    sync::oneshot,
    task::JoinHandle,
    time,
};

use crate::{
    AppError, Result, auth::session::Session, error::ApiResponse, http::middleware::CurrentSession,
    state::AppState, system::script_supervisor,
};

pub const MAX_SCRIPT_BYTES: usize = 256 * 1024;
/// Scripts kept at most. With the size limit this keeps the directory far below
/// what a raw update can carry.
const MAX_SCRIPT_FILES: usize = 64;
/// A mode of this static helper. Not of the backend: starting NanoKVM-Server
/// loads the vendor libraries, which take the video devices from the running
/// backend and keep the process from ever exiting.
const SUPERVISOR: &str = "/usr/libexec/nanokvm-native-ctl";
/// Carries a terminal unlock ticket for exactly one script upload or run.
pub const UNLOCK_HEADER: &str = "x-nanokvm-terminal-ticket";
/// Output kept per stream; anything beyond it is read and discarded.
const MAX_SCRIPT_OUTPUT_BYTES: usize = 64 * 1024;
const SCRIPT_DIRECTORY: &str = "/etc/kvm/scripts";

/// Bounds of one foreground run.
#[derive(Clone, Copy)]
struct RunLimits {
    /// Then the script's process group gets SIGTERM.
    timeout: Duration,
    /// Then SIGKILL.
    grace: Duration,
    /// How long a process left behind may keep the output pipes open.
    drain: Duration,
}

const RUN_LIMITS: RunLimits = RunLimits {
    timeout: Duration::from_secs(60),
    grace: Duration::from_secs(2),
    drain: Duration::from_secs(2),
};

#[derive(Debug, Serialize)]
pub struct GetScriptsRsp {
    pub files: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct UploadScriptRsp {
    pub file: String,
}

#[derive(Debug, Deserialize)]
pub struct DeleteScriptReq {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct RunScriptReq {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Serialize)]
pub struct RunScriptRsp {
    pub log: String,
}

pub async fn get_scripts() -> Result<impl IntoResponse> {
    let mut files = Vec::new();
    let dir = Path::new(SCRIPT_DIRECTORY);
    if dir.exists() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_file() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if is_script_name(&name) {
                files.push(name);
            }
        }
    }
    files.sort();

    Ok(Json(ApiResponse::ok(GetScriptsRsp { files })))
}

// Scripts run as root, so they pass the terminal's gate: terminal access is
// enabled, and each upload or run consumes a fresh unlock ticket of this
// session, issued after its password was entered again.
async fn require_terminal_unlock(
    state: &AppState,
    session: Option<&Session>,
    headers: &HeaderMap,
) -> Result<()> {
    let session = match session {
        Some(session) if !state.config.auth_disabled() && state.terminal_enabled() => session,
        _ => return Err(AppError::Forbidden("terminal is disabled".to_string())),
    };
    let ticket = headers
        .get(UNLOCK_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if ticket.is_empty() || !state.terminal_tickets.consume(ticket, session).await {
        return Err(AppError::Forbidden(
            "terminal unlock is required".to_string(),
        ));
    }
    Ok(())
}

pub async fn upload_script(
    State(state): State<AppState>,
    session: Option<Extension<CurrentSession>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<impl IntoResponse> {
    let session = session.map(|Extension(CurrentSession(session))| session);
    require_terminal_unlock(&state, session.as_ref(), &headers).await?;
    let mut uploaded = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|err| AppError::BadRequest(format!("invalid multipart script upload: {err}")))?
    {
        if field.name() != Some("file") {
            continue;
        }
        let filename = field
            .file_name()
            .ok_or_else(|| AppError::BadRequest("missing script filename".to_string()))?
            .to_string();
        let filename = validate_new_script_name(&filename)?;
        let data = field
            .bytes()
            .await
            .map_err(|err| AppError::BadRequest(format!("read script upload failed: {err}")))?;
        if data.len() > MAX_SCRIPT_BYTES {
            return Err(AppError::BadRequest("script file is too large".to_string()));
        }
        if data.is_empty() {
            return Err(AppError::BadRequest("script file is empty".to_string()));
        }

        let writer = state.writers.configuration()?;
        let write_name = filename.clone();
        let write_data = data.to_vec();
        writer
            .run(move |writer| async move {
                writer
                    .blocking(move |_permit| write_script_file(&write_name, &write_data))
                    .await
            })
            .await?;
        uploaded = Some(filename);
        break;
    }

    let file = uploaded.ok_or_else(|| AppError::BadRequest("missing script file".to_string()))?;
    Ok(Json(ApiResponse::ok(UploadScriptRsp { file })))
}

pub async fn delete_script(
    State(state): State<AppState>,
    session: Option<Extension<CurrentSession>>,
    headers: HeaderMap,
    Json(req): Json<DeleteScriptReq>,
) -> Result<impl IntoResponse> {
    let session = session.map(|Extension(CurrentSession(session))| session);
    require_terminal_unlock(&state, session.as_ref(), &headers).await?;
    let writer = state.writers.configuration()?;
    let path = checked_script_path(&req.name)?;
    writer
        .run(move |writer| async move {
            writer
                .blocking(move |_permit| remove_script_file(&path))
                .await
        })
        .await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn run_script(
    State(state): State<AppState>,
    session: Option<Extension<CurrentSession>>,
    headers: HeaderMap,
    Json(req): Json<RunScriptReq>,
) -> Result<impl IntoResponse> {
    let session = session.map(|Extension(CurrentSession(session))| session);
    require_terminal_unlock(&state, session.as_ref(), &headers).await?;
    let path = checked_script_path(&req.name)?;
    match req.kind.as_str() {
        "foreground" => {
            let command = supervised_command(script_command(&path)?, RUN_LIMITS);
            let log = run_script_foreground(command, RUN_LIMITS).await?;
            Ok(Json(ApiResponse::ok(RunScriptRsp { log })))
        }
        "background" => {
            run_script_background(&path)?;
            Ok(Json(ApiResponse::ok(RunScriptRsp { log: String::new() })))
        }
        _ => Err(AppError::BadRequest("invalid script run type".to_string())),
    }
}

fn validate_script_name(name: &str) -> Result<String> {
    let name = name.trim();
    if !is_script_name(name) {
        return Err(AppError::BadRequest("invalid script filename".to_string()));
    }
    if name.contains('/') || name.contains('\\') || name == "." || name == ".." {
        return Err(AppError::BadRequest("invalid script filename".to_string()));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(AppError::BadRequest("invalid script filename".to_string()));
    }
    Ok(name.to_string())
}

/// The name of a script to store. Stricter than the names that can be listed,
/// run and deleted: a raw update refuses a script directory that holds a name
/// it does not carry, so no such name may enter it.
fn validate_new_script_name(name: &str) -> Result<String> {
    let name = validate_script_name(name)?;
    if !crate::update::restore_carries(&format!("etc/kvm/scripts/{name}")) {
        return Err(AppError::BadRequest("invalid script filename".to_string()));
    }
    Ok(name)
}

fn is_script_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    (lower.ends_with(".sh") || lower.ends_with(".py")) && name.len() <= 128 && name.len() > 3
}

fn script_path(name: &str) -> Result<PathBuf> {
    Ok(Path::new(SCRIPT_DIRECTORY).join(validate_script_name(name)?))
}

fn checked_script_path(name: &str) -> Result<PathBuf> {
    let path = script_path(name)?;
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::BadRequest("invalid script file".to_string()));
    }
    Ok(path)
}

fn write_script_file(name: &str, data: &[u8]) -> Result<()> {
    store_script(Path::new(SCRIPT_DIRECTORY), name, data)
}

/// Store one script in `directory`. The caller holds the configuration permit,
/// so no other upload is in flight.
fn store_script(directory: &Path, name: &str, data: &[u8]) -> Result<()> {
    let path = directory.join(validate_new_script_name(name)?);
    let replaces = match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(AppError::BadRequest("invalid script file".to_string()));
        }
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    let mut stored = 0;
    if directory.exists() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            // What an upload cut short by power loss left behind.
            if entry
                .file_name()
                .to_str()
                .is_some_and(crate::system::files::is_abandoned_temp)
            {
                fs::remove_file(entry.path())?;
                continue;
            }
            stored += 1;
        }
    }
    if !replaces && stored >= MAX_SCRIPT_FILES {
        return Err(AppError::BadRequest(format!(
            "at most {MAX_SCRIPT_FILES} scripts are kept; delete one first"
        )));
    }
    crate::system::files::write_atomic(&path, data, 0o755)
}

fn remove_script_file(path: &Path) -> Result<()> {
    fs::remove_file(path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Run a script to completion in its own task: a closed browser tab does not
/// kill a root script halfway. The run's timeout is its only cancellation.
async fn run_script_foreground(command: Command, limits: RunLimits) -> Result<String> {
    let (reply, result) = oneshot::channel();
    tokio::spawn(async move {
        drop(reply.send(run_foreground(command, limits).await));
    });
    result
        .await
        .map_err(|_| AppError::Internal("script run ended without a result".to_string()))?
}

fn supervised_command(command: Command, limits: RunLimits) -> Command {
    let standard = command.as_std();
    let program = standard.get_program().to_os_string();
    let arguments: Vec<_> = standard.get_args().map(|arg| arg.to_os_string()).collect();
    let mut supervised = Command::new(SUPERVISOR);
    supervised
        .arg("--script-supervisor")
        .arg(limits.timeout.as_secs().to_string())
        .arg(limits.grace.as_millis().to_string())
        .arg("--")
        .arg(program)
        .args(arguments);
    supervised
}

async fn run_foreground(mut command: Command, limits: RunLimits) -> Result<String> {
    // Its own process group, so a timeout ends every process the script
    // started that stayed in it; `setsid` escapes this, as in a shell.
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()?;
    let mut stdout = Captured::drain(child.stdout.take());
    let mut stderr = Captured::drain(child.stderr.take());
    let wait_limit = limits.timeout + limits.grace + Duration::from_secs(2);
    let status = match time::timeout(wait_limit, child.wait()).await {
        Ok(status) => Some(status?),
        Err(_) => {
            stop_group(&mut child, limits.grace).await?;
            None
        }
    };
    // A process left behind may still hold the pipes; it gets a short while.
    let deadline = time::Instant::now() + limits.drain;
    let stdout_complete = stdout.finish(deadline).await;
    let complete = stderr.finish(deadline).await && stdout_complete;
    let Some(status) = status else {
        return Err(AppError::Internal(
            "script timed out; its process group was stopped".to_string(),
        ));
    };
    if status.code() == Some(script_supervisor::LEFT_BEHIND) {
        return Err(AppError::Internal(
            "the script ended, but processes it started could not be stopped".to_string(),
        ));
    }
    if status.code() == Some(124) {
        return Err(AppError::Internal(
            "script timed out; its process tree was stopped".to_string(),
        ));
    }
    if !status.success() {
        return Err(AppError::Internal("run script failed".to_string()));
    }
    let mut log = stdout.text();
    log.push_str(&stderr.text());
    if stdout.truncated() || stderr.truncated() {
        log.push_str("\n[output truncated: only the first 64 KiB of each stream is kept]\n");
    }
    if !complete {
        log.push_str("\n[output incomplete: a process left running still held it]\n");
    }
    Ok(log)
}

/// SIGTERM to the script's process group, SIGKILL after `grace`, then reap.
/// Until the leader is reaped, its ID, which names the group, cannot be reused.
async fn stop_group(child: &mut Child, grace: Duration) -> Result<ExitStatus> {
    let group = child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .map(Pid::from_raw);
    if let Some(group) = group {
        let _ = killpg(group, Signal::SIGTERM);
        time::sleep(grace).await;
        let _ = killpg(group, Signal::SIGKILL);
    }
    Ok(child.wait().await?)
}

/// One output stream: the first MAX_SCRIPT_OUTPUT_BYTES are kept, the rest is
/// read and discarded, so a chatty script never blocks on a full pipe.
struct Captured {
    state: Arc<Mutex<(Vec<u8>, bool)>>,
    reader: Option<JoinHandle<()>>,
}

impl Captured {
    fn drain<R: AsyncRead + Unpin + Send + 'static>(reader: Option<R>) -> Self {
        let state = Arc::new(Mutex::new((Vec::new(), false)));
        let reader = reader.map(|mut reader| {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let mut chunk = [0_u8; 4096];
                while let Ok(read) = reader.read(&mut chunk).await {
                    if read == 0 {
                        break;
                    }
                    let mut state = state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let keep = MAX_SCRIPT_OUTPUT_BYTES
                        .saturating_sub(state.0.len())
                        .min(read);
                    state.0.extend_from_slice(&chunk[..keep]);
                    state.1 |= keep < read;
                }
            })
        });
        Self { state, reader }
    }

    /// Wait for EOF until `deadline`; past it, stop reading. True at EOF.
    async fn finish(&mut self, deadline: time::Instant) -> bool {
        let Some(reader) = self.reader.as_mut() else {
            return true;
        };
        let finished = time::timeout_at(deadline, &mut *reader).await.is_ok();
        if !finished {
            reader.abort();
        }
        finished
    }

    fn text(&self) -> String {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        String::from_utf8_lossy(&state.0).into_owned()
    }

    fn truncated(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .1
    }
}

fn run_script_background(path: &Path) -> Result<()> {
    script_command(path)?
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(())
}

fn script_command(path: &Path) -> Result<Command> {
    let extension = path
        .extension()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if extension == "py" {
        let mut command = Command::new("python");
        command.arg(path);
        Ok(command)
    } else if extension == "sh" {
        // A raw update keeps uploads as inert data, without the execute bit, so
        // only this explicit run gives a script any effect.
        let mut command = Command::new("/bin/sh");
        command.arg(path);
        Ok(command)
    } else {
        Err(AppError::BadRequest("invalid script filename".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    const LIMITS: RunLimits = RunLimits {
        timeout: Duration::from_secs(1),
        grace: Duration::from_millis(300),
        drain: Duration::from_millis(500),
    };

    /// Run through `/bin/sh`: executing a file just written races with
    /// parallel tests that fork while it is still open (ETXTBSY).
    fn script(dir: &tempfile::TempDir, name: &str, body: &str) -> Command {
        let path = dir.path().join(name);
        fs::write(&path, format!("{body}\n")).unwrap();
        let mut command = Command::new("/bin/sh");
        command.arg(path);
        command
    }

    #[test]
    fn the_supervisor_is_the_static_helper_and_not_the_backend() {
        let mut script = Command::new("/bin/sh");
        script.arg("/etc/kvm/scripts/job.sh");
        let supervised = supervised_command(script, LIMITS);
        let standard = supervised.as_std();
        assert_eq!(standard.get_program(), "/usr/libexec/nanokvm-native-ctl");
        assert_eq!(
            standard.get_args().collect::<Vec<_>>(),
            [
                "--script-supervisor",
                "1",
                "300",
                "--",
                "/bin/sh",
                "/etc/kvm/scripts/job.sh"
            ]
        );
    }

    #[tokio::test]
    async fn processes_left_behind_are_a_failure_with_their_own_message() {
        let dir = tempfile::tempdir().unwrap();
        let command = script(
            &dir,
            "left.sh",
            &format!("exit {}", script_supervisor::LEFT_BEHIND),
        );
        let error = run_foreground(command, LIMITS).await.unwrap_err();
        assert!(
            error.to_string().contains("could not be stopped"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_script_without_the_execute_bit_runs_when_asked() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("restored.sh");
        fs::write(&path, "exit 7\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let status = script_command(&path).unwrap().status().await.unwrap();
        assert_eq!(status.code(), Some(7));
    }

    /// Running or stopped; a zombie counts as ended.
    fn alive(pid: i32) -> bool {
        fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
            stat.rsplit_once(") ")
                .is_some_and(|(_, rest)| !rest.starts_with('Z'))
        })
    }

    async fn ends(pid: i32) -> bool {
        for _ in 0..150 {
            if !alive(pid) {
                return true;
            }
            time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    #[tokio::test]
    async fn a_chatty_script_finishes_with_its_output_cut_at_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        // 1 MiB on stdout, far beyond the cap and the pipe buffer.
        let command = script(
            &dir,
            "chatty.sh",
            "head -c 1048576 /dev/zero | tr '\\000' a\necho done >&2",
        );
        let started = Instant::now();
        let log = run_script_foreground(command, LIMITS).await.unwrap();
        assert!(started.elapsed() < LIMITS.timeout);
        let (kept, rest) = log.split_at(MAX_SCRIPT_OUTPUT_BYTES);
        assert!(kept.bytes().all(|byte| byte == b'a'));
        assert!(rest.starts_with("done\n"), "{rest}");
        assert!(rest.contains("[output truncated"));
        assert!(matches!(
            run_script_foreground(script(&dir, "fail.sh", "exit 3"), LIMITS).await,
            Err(AppError::Internal(ref text)) if text == "run script failed"
        ));
    }

    #[tokio::test]
    async fn a_timed_out_script_and_everything_it_started_are_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let pids = dir.path().join("pids");
        // The background job ignores SIGTERM; only the later SIGKILL ends it.
        let body = format!(
            "(trap '' TERM; exec sleep 300) &\necho $! > {0}\necho $$ >> {0}\nexec sleep 300",
            pids.display()
        );
        let started = Instant::now();
        let result = run_script_foreground(script(&dir, "stuck.sh", &body), LIMITS).await;
        assert!(
            matches!(result, Err(AppError::Internal(ref text)) if text.contains("timed out")),
            "{result:?}"
        );
        assert!(started.elapsed() >= LIMITS.timeout + LIMITS.grace);
        let pids: Vec<i32> = fs::read_to_string(&pids)
            .unwrap()
            .lines()
            .map(|line| line.parse().unwrap())
            .collect();
        assert_eq!(pids.len(), 2);
        for pid in pids {
            assert!(ends(pid).await, "process {pid} survived the timeout");
        }
    }

    #[tokio::test]
    async fn a_lost_client_does_not_stop_the_run() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("finished");
        let body = format!("sleep 0.5\necho finished > {}", marker.display());
        let request = tokio::spawn(run_script_foreground(
            script(&dir, "slow.sh", &body),
            LIMITS,
        ));
        time::sleep(Duration::from_millis(100)).await;
        // The HTTP handler's future is dropped when its client goes away.
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        for _ in 0..100 {
            if marker.exists() {
                break;
            }
            time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(fs::read_to_string(&marker).unwrap(), "finished\n");
    }

    #[tokio::test]
    async fn a_process_left_holding_the_output_does_not_hold_the_reply() {
        let dir = tempfile::tempdir().unwrap();
        let pid = dir.path().join("pid");
        let body = format!("sleep 300 &\necho $! > {}\necho started", pid.display());
        let started = Instant::now();
        let log = run_script_foreground(script(&dir, "daemon.sh", &body), LIMITS)
            .await
            .unwrap();
        assert!(started.elapsed() < LIMITS.timeout);
        assert!(log.starts_with("started\n"), "{log}");
        assert!(log.contains("[output incomplete"));
        // A finished script's background job keeps running, as before.
        let pid: i32 = fs::read_to_string(&pid).unwrap().trim().parse().unwrap();
        assert!(alive(pid));
        let _ = nix::sys::signal::kill(Pid::from_raw(pid), Signal::SIGKILL);
    }

    #[test]
    fn accepts_simple_script_names() {
        assert_eq!(validate_script_name("test.sh").unwrap(), "test.sh");
        assert_eq!(
            validate_script_name("hello_world-1.py").unwrap(),
            "hello_world-1.py"
        );
    }

    #[test]
    fn a_new_script_gets_only_a_name_that_a_raw_update_carries() {
        for name in ["test.sh", "hello_world-1.py", "a.b.sh", "UPPER.SH"] {
            assert_eq!(validate_new_script_name(name).unwrap(), name);
        }
        // A hidden name can still be listed, run and deleted, so that a script
        // an earlier version accepted can be removed, but not stored again.
        for name in [".hidden.sh", ".a.py", "..sh"] {
            assert!(validate_script_name(name).is_ok(), "{name}");
            assert!(validate_new_script_name(name).is_err(), "{name}");
        }
        // Every name an upload may get is one the restore policy carries.
        let alphabet = [".", "a", "Z", "0", "_", "-", ".sh", ".py", " ", "/", "x.sh"];
        for first in alphabet {
            for second in alphabet {
                for third in alphabet {
                    // The name that is stored is the one the validator returns.
                    let name = format!("{first}{second}{third}");
                    if let Ok(stored) = validate_new_script_name(&name) {
                        assert!(
                            crate::update::restore_carries(&format!("etc/kvm/scripts/{stored}")),
                            "{name:?} is stored as {stored:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn storing_a_script_keeps_the_directory_small_and_free_of_leftovers() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("scripts");
        // The directory is created with the first script.
        store_script(&dir, "first.sh", b"echo 1\n").unwrap();
        assert_eq!(
            fs::metadata(dir.join("first.sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );
        assert!(store_script(&dir, ".hidden.sh", b"echo\n").is_err());
        // An upload that power loss cut short is removed by the next one.
        let leftover = dir.join(".first.sh.812.4.00ff00ff00ff00ff.tmp");
        fs::write(&leftover, b"half").unwrap();
        fs::write(
            dir.join(".kept.sh"),
            b"a script an earlier version accepted",
        )
        .unwrap();
        store_script(&dir, "second.py", b"print(2)\n").unwrap();
        assert!(!leftover.exists());
        assert!(dir.join(".kept.sh").exists());

        // Three files are stored. At the limit a new name is refused, an
        // existing one is still replaced, and a deletion makes room.
        for index in 3..MAX_SCRIPT_FILES {
            store_script(&dir, &format!("s{index}.sh"), b"echo\n").unwrap();
        }
        assert_eq!(fs::read_dir(&dir).unwrap().count(), MAX_SCRIPT_FILES);
        assert!(matches!(
            store_script(&dir, "one-more.sh", b"echo\n"),
            Err(AppError::BadRequest(_))
        ));
        store_script(&dir, "first.sh", b"echo replaced\n").unwrap();
        assert_eq!(fs::read(dir.join("first.sh")).unwrap(), b"echo replaced\n");
        fs::remove_file(dir.join("second.py")).unwrap();
        store_script(&dir, "one-more.sh", b"echo\n").unwrap();

        // A link in place of a script is refused and its target kept.
        let target = root.path().join("target");
        fs::write(&target, b"untouched").unwrap();
        fs::remove_file(dir.join("s3.sh")).unwrap();
        symlink(&target, dir.join("s3.sh")).unwrap();
        assert!(store_script(&dir, "s3.sh", b"echo\n").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"untouched");
    }

    #[test]
    fn rejects_unsafe_script_names() {
        assert!(validate_script_name("../x.sh").is_err());
        assert!(validate_script_name("x.txt").is_err());
        assert!(validate_script_name("bad name.sh").is_err());
        assert!(validate_script_name("x.sh/evil").is_err());
    }

    #[tokio::test]
    async fn script_operations_need_terminal_access_and_a_fresh_unlock_of_this_session() {
        use std::sync::atomic::Ordering;
        let mut config = crate::config::Config {
            stun: "disable".into(),
            ..crate::config::Config::default()
        };
        config.security.allow_terminal = true;
        let state = AppState::new(config).await.unwrap();
        let session = state.sessions.issue("admin", 60).await;
        let other = state.sessions.issue("admin", 60).await;
        let header = |ticket: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(UNLOCK_HEADER, ticket.parse().unwrap());
            headers
        };
        let refused = |result: Result<()>| matches!(result, Err(AppError::Forbidden(_)));
        assert!(refused(
            require_terminal_unlock(&state, None, &HeaderMap::new()).await
        ));
        assert!(refused(
            require_terminal_unlock(&state, Some(&session), &HeaderMap::new()).await
        ));
        let foreign = state.terminal_tickets.issue(&other, 120).await;
        assert!(refused(
            require_terminal_unlock(&state, Some(&session), &header(&foreign.token)).await
        ));
        // A fresh ticket of this session admits exactly one operation.
        let ticket = state.terminal_tickets.issue(&session, 120).await;
        require_terminal_unlock(&state, Some(&session), &header(&ticket.token))
            .await
            .unwrap();
        assert!(refused(
            require_terminal_unlock(&state, Some(&session), &header(&ticket.token)).await
        ));
        // With terminal access off, even a fresh ticket is refused.
        state.terminal_enabled.store(false, Ordering::SeqCst);
        let ticket = state.terminal_tickets.issue(&session, 120).await;
        assert!(refused(
            require_terminal_unlock(&state, Some(&session), &header(&ticket.token)).await
        ));
    }

    #[tokio::test]
    async fn delete_script_requires_a_fresh_terminal_unlock() {
        let mut config = crate::config::Config {
            stun: "disable".into(),
            ..crate::config::Config::default()
        };
        config.security.allow_terminal = true;
        let state = AppState::new(config).await.unwrap();
        let request = Json(DeleteScriptReq {
            name: "job.sh".to_string(),
        });
        let result = delete_script(State(state), None, HeaderMap::new(), request).await;
        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
