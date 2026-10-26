//! Bounded direct-child enumeration for the native supervisors.
//!
//! `/proc/<pid>/task/<tid>/children` is preferred, but it is only available
//! when the kernel was built with `CONFIG_PROC_CHILDREN`. The fallback scans
//! `/proc/<pid>/stat` and selects only processes whose parent is the supervisor.
//! A PID from either source is only a candidate: `signal_child` still verifies
//! the pidfd names our child before sending a signal.

use rustix::{
    io::Errno,
    process::{
        Pid, PidfdFlags, Signal, WaitId, WaitIdOptions, pidfd_open, pidfd_send_signal, waitid,
    },
};
use std::{
    fs::{self, File},
    io::{self, Read},
    os::fd::AsFd,
    path::Path,
};

pub(crate) const MAX_CHILDREN: usize = 4096;
const MAX_TASK_CHILDREN_BYTES: u64 = 64 * 1024;
const PEEK: WaitIdOptions = WaitIdOptions::EXITED
    .union(WaitIdOptions::NOHANG)
    .union(WaitIdOptions::NOWAIT)
    .union(WaitIdOptions::from_bits_retain(nix::libc::__WALL as u32));

/// Return the supervisor's first-level children. The task-children file is
/// authoritative when present; a kernel without it falls back to `/proc` stat
/// scanning. A missing or malformed child list is an error, never an empty
/// success.
pub(crate) fn direct_children(proc_root: &Path, parent: Pid) -> io::Result<Vec<Pid>> {
    let raw_parent = parent.as_raw_nonzero().get();
    let task_children = proc_root.join(format!("{raw_parent}/task/{raw_parent}/children"));
    match File::open(&task_children) {
        Ok(file) => parse_task_children(file),
        Err(error) if error.kind() == io::ErrorKind::NotFound => scan_proc(proc_root, raw_parent),
        Err(error) => Err(error),
    }
}

/// The candidate must still be our unreaped child. This keeps PROC_CHILDREN
/// and fallback enumeration at the same trust boundary: proc entries nominate,
/// the kernel pidfd/waitid pair authorizes.
pub(crate) fn signal_child(pid: Pid, signal: Signal) -> io::Result<()> {
    let fd = match pidfd_open(pid, PidfdFlags::empty()) {
        Ok(fd) => fd,
        Err(Errno::SRCH) => return Ok(()),
        Err(error) => return Err(io::Error::from(error)),
    };
    match waitid(WaitId::PidFd(fd.as_fd()), PEEK) {
        Ok(None) => {}
        Ok(Some(_)) | Err(Errno::CHILD) => return Ok(()),
        Err(error) => return Err(io::Error::from(error)),
    }
    match pidfd_send_signal(&fd, signal) {
        Ok(()) | Err(Errno::SRCH) => Ok(()),
        Err(error) => Err(io::Error::from(error)),
    }
}

fn parse_task_children(file: File) -> io::Result<Vec<Pid>> {
    let bytes = read_limited(file, MAX_TASK_CHILDREN_BYTES)?;
    let mut children = Vec::new();
    for token in bytes.split(|byte| byte.is_ascii_whitespace()) {
        if token.is_empty() {
            continue;
        }
        let text = std::str::from_utf8(token)
            .map_err(|_| invalid("task children contain non-UTF-8 data"))?;
        let raw = text
            .parse::<i32>()
            .map_err(|_| invalid("task children contain a non-numeric PID"))?;
        let pid =
            Pid::from_raw(raw).ok_or_else(|| invalid("task children contain an invalid PID"))?;
        if raw <= 1 {
            return Err(invalid("task children contain PID 0 or 1"));
        }
        push_child(&mut children, pid)?;
    }
    Ok(children)
}

fn scan_proc(proc_root: &Path, parent: i32) -> io::Result<Vec<Pid>> {
    let mut children = Vec::new();
    for entry in fs::read_dir(proc_root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Ok(raw) = name.parse::<i32>() else {
            continue;
        };
        if raw <= 1 || raw == parent {
            continue;
        }
        let pid =
            Pid::from_raw(raw).ok_or_else(|| invalid("proc contains an invalid process ID"))?;
        let stat = match File::open(entry.path().join("stat")) {
            Ok(file) => read_limited(file, MAX_TASK_CHILDREN_BYTES)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if parse_ppid(&stat)? == parent {
            push_child(&mut children, pid)?;
        }
    }
    Ok(children)
}

fn parse_ppid(stat: &[u8]) -> io::Result<i32> {
    let text = std::str::from_utf8(stat).map_err(|_| invalid("process stat is not UTF-8"))?;
    let end = text
        .rfind(") ")
        .ok_or_else(|| invalid("process stat has no command terminator"))?;
    let mut fields = text[end + 2..].split_ascii_whitespace();
    let _state = fields
        .next()
        .ok_or_else(|| invalid("process stat has no state"))?;
    fields
        .next()
        .ok_or_else(|| invalid("process stat has no parent"))?
        .parse::<i32>()
        .map_err(|_| invalid("process stat parent is not numeric"))
}

fn push_child(children: &mut Vec<Pid>, pid: Pid) -> io::Result<()> {
    if children.len() >= MAX_CHILDREN {
        return Err(invalid("too many direct children"));
    }
    children.push(pid);
    children.sort_unstable_by_key(|pid| pid.as_raw_nonzero().get());
    children.dedup();
    Ok(())
}

fn read_limited(file: File, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("proc child list exceeded its bound"));
    }
    Ok(bytes)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn parent() -> Pid {
        Pid::from_raw(123).unwrap()
    }

    fn stat(pid: i32, comm: &str, ppid: i32) -> String {
        format!(
            "{pid} ({comm}) S {ppid} 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
        )
    }

    #[test]
    fn task_children_file_is_preferred_and_sorted() {
        let root = tempfile::tempdir().unwrap();
        let task = root.path().join("123/task/123");
        fs::create_dir_all(&task).unwrap();
        fs::write(task.join("children"), "9 7\n").unwrap();
        let children = direct_children(root.path(), parent()).unwrap();
        assert_eq!(
            children,
            [Pid::from_raw(7).unwrap(), Pid::from_raw(9).unwrap()]
        );
    }

    #[test]
    fn empty_task_children_file_is_authoritative() {
        let root = tempfile::tempdir().unwrap();
        let task = root.path().join("123/task/123");
        fs::create_dir_all(&task).unwrap();
        fs::write(task.join("children"), "").unwrap();
        let child = root.path().join("456");
        fs::create_dir_all(&child).unwrap();
        fs::write(child.join("stat"), stat(456, "worker", 123)).unwrap();
        assert!(direct_children(root.path(), parent()).unwrap().is_empty());
    }

    #[test]
    fn missing_task_file_falls_back_to_proc_stat() {
        let root = tempfile::tempdir().unwrap();
        for (pid, ppid) in [(456, 123), (457, 999), (1, 0), (123, 123)] {
            let dir = root.path().join(pid.to_string());
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("stat"), stat(pid, "worker", ppid)).unwrap();
        }
        let children = direct_children(root.path(), parent()).unwrap();
        assert_eq!(children, [Pid::from_raw(456).unwrap()]);
    }

    #[test]
    fn fallback_parses_a_command_name_containing_parens() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("456");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("stat"), stat(456, "a) b", 123)).unwrap();
        assert_eq!(
            direct_children(root.path(), parent()).unwrap(),
            [Pid::from_raw(456).unwrap()]
        );
    }

    #[test]
    fn malformed_task_file_is_not_treated_as_empty() {
        let root = tempfile::tempdir().unwrap();
        let task = root.path().join("123/task/123");
        fs::create_dir_all(&task).unwrap();
        fs::write(task.join("children"), "not-a-pid\n").unwrap();
        assert!(direct_children(root.path(), parent()).is_err());
    }

    #[test]
    fn malformed_stat_is_an_error() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("456");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("stat"), "not a stat line\n").unwrap();
        assert!(direct_children(root.path(), parent()).is_err());
    }

    #[test]
    fn task_children_bound_is_enforced() {
        let root = tempfile::tempdir().unwrap();
        let task = root.path().join("123/task/123");
        fs::create_dir_all(&task).unwrap();
        let mut list = String::new();
        for pid in 0..=MAX_CHILDREN {
            list.push_str(&format!("{}\n", pid + 2));
        }
        fs::write(task.join("children"), list).unwrap();
        assert!(direct_children(root.path(), parent()).is_err());
    }
}
