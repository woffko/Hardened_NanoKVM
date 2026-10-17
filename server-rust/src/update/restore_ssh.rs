//! Closed SSH server authority guard over an immutable restore snapshot.
//! It does not replace signed sshd -t/-T, host-key parsing or a real login gate.

use super::restore_archive::{
    self, CanonicalSetting, RestoreAction, RestoreArchiveError, SourceRoot, ValidatedRestore,
};
use std::{
    collections::BTreeSet,
    io::{self, Write},
    path::Path,
};
use zeroize::Zeroizing;

#[path = "restore_ssh_key_probe.rs"]
mod key_probe;
#[path = "restore_ssh_lexer.rs"]
mod lexer;
#[path = "restore_ssh_policy.rs"]
mod policy;

const MAIN: &str = "etc/ssh/sshd_config";
const CONFIG_DIRECTORY: &str = "etc/ssh/sshd_config.d";
const MAX_CONFIG: usize = 64 * 1024;
const MAX_CONFIG_TOTAL: usize = 512 * 1024;
const MAX_DATA: usize = 4 * 1024 * 1024;
const MAX_TOTAL: usize = 8 * 1024 * 1024;
const MAX_FILES: usize = 128;
const HOST_KEYS: &[&str] = &[
    "etc/ssh/ssh_host_rsa_key",
    "etc/ssh/ssh_host_ecdsa_key",
    "etc/ssh/ssh_host_ed25519_key",
];
const FLAGS: &[&str] = &["etc/kvm/ssh_stop", "boot/start_ssh_once"];
const FILES: &[&str] = &[
    MAIN,
    "etc/ssh/moduli",
    "etc/ssh/ssh_host_rsa_key",
    "etc/ssh/ssh_host_rsa_key.pub",
    "etc/ssh/ssh_host_ecdsa_key",
    "etc/ssh/ssh_host_ecdsa_key.pub",
    "etc/ssh/ssh_host_ed25519_key",
    "etc/ssh/ssh_host_ed25519_key.pub",
    "etc/ssh/ssh_host_rsa_key-cert.pub",
    "etc/ssh/ssh_host_ecdsa_key-cert.pub",
    "etc/ssh/ssh_host_ed25519_key-cert.pub",
    "etc/ssh/banner",
    "etc/ssh/trusted-user-ca-keys.pub",
    "etc/ssh/revoked_keys",
    "etc/ssh/authorized_principals",
    "etc/ssh/ssh_known_hosts",
    "etc/ssh/shosts.equiv",
    "etc/hosts.equiv",
    "root/.rhosts",
    "root/.shosts",
    "root/.ssh/authorized_keys",
    "root/.ssh/authorized_keys2",
];

#[derive(Debug, thiserror::Error)]
pub enum SshRestoreError {
    #[error("SSH restore configuration is invalid or incomplete")]
    Invalid,
    #[error("SSH restore state exceeds its resource budget")]
    Limit,
    #[error("SSH restore authority/layout requires an explicit verified migration")]
    Unsupported,
    #[error("SSH private key is invalid, unusable or does not match its public identity")]
    InvalidKey,
    #[error("SSH key preflight runtime failed")]
    ProbeRuntime,
    #[error("SSH key preflight exceeded its time budget")]
    ProbeTimeout,
    #[error(transparent)]
    Archive(#[from] RestoreArchiveError),
}
type Result<T> = std::result::Result<T, SshRestoreError>;

struct File {
    path: String,
    bytes: Zeroizing<Vec<u8>>,
}
pub(super) struct Snapshot {
    files: Vec<File>,
    absent: Vec<&'static str>,
}
impl Snapshot {
    pub(super) fn capture(source: &SourceRoot) -> Result<Self> {
        // These autoloaded files are outside the current inert-data schema.
        // Never silently omit them or import executable startup hooks as data.
        for path in ["etc/ssh/sshrc", "root/.ssh/rc", "root/.ssh/environment"] {
            if source.metadata(path)?.is_some() {
                return Err(SshRestoreError::Unsupported);
            }
        }
        let mut paths = BTreeSet::new();
        let mut absent = Vec::with_capacity(FILES.len() + FLAGS.len());
        for path in FILES.iter().chain(FLAGS) {
            if source.metadata(path)?.is_some() {
                paths.insert((*path).to_string());
            } else {
                absent.push(*path);
            }
        }
        let mut scanned = 0;
        restore_archive::collect_tree(source, CONFIG_DIRECTORY, &mut paths, 0, &mut scanned)?;
        if paths.len() > MAX_FILES {
            return Err(SshRestoreError::Limit);
        }
        let mut files = Vec::with_capacity(paths.len());
        let mut total = 0;
        for path in paths {
            let limit = file_limit(&path);
            let bytes = source
                .read_setting(&path, limit)?
                .ok_or(SshRestoreError::Invalid)?;
            total += bytes.len();
            if total > MAX_TOTAL {
                return Err(SshRestoreError::Limit);
            }
            files.push(File { path, bytes });
        }
        let enabled =
            !files.iter().any(|f| f.path == FLAGS[0]) || files.iter().any(|f| f.path == FLAGS[1]);
        check(&files, enabled)?;
        Ok(Self { files, absent })
    }
    pub(super) fn len(&self) -> usize {
        self.files.len() + self.absent.len()
    }
    pub(super) fn take_settings(&mut self) -> Vec<CanonicalSetting<'_>> {
        let mut result = Vec::with_capacity(self.len());
        for file in &mut self.files {
            result.push(CanonicalSetting {
                path: &file.path,
                bytes: Some(std::mem::take(&mut file.bytes)),
            });
        }
        for path in &self.absent {
            result.push(CanonicalSetting { path, bytes: None });
        }
        result
    }
}

pub(super) fn check_archive(archive: &mut ValidatedRestore) -> Result<()> {
    let mut indexes = Vec::with_capacity(MAX_FILES);
    for (index, member) in archive.members().iter().enumerate() {
        if FLAGS.contains(&member.path.as_str()) && member.action == RestoreAction::Absent {
            continue;
        }
        if runtime_file(&member.path) || FLAGS.contains(&member.path.as_str()) {
            if indexes.len() == MAX_FILES {
                return Err(SshRestoreError::Limit);
            }
            indexes.push(index);
        }
    }
    let mut files = Vec::with_capacity(indexes.len());
    let mut total = 0;
    for index in indexes {
        let member = &archive.members()[index];
        let limit = file_limit(&member.path);
        if member.action != RestoreAction::Write || member.size > limit as u64 {
            return Err(SshRestoreError::Limit);
        }
        total += member.size as usize;
        if total > MAX_TOTAL {
            return Err(SshRestoreError::Limit);
        }
        let path = member.path.clone();
        let mut out = BoundedBytes {
            bytes: Zeroizing::new(Vec::with_capacity(member.size as usize)),
            limit,
        };
        archive.copy_file(index, &mut out)?;
        files.push(File {
            path,
            bytes: out.bytes,
        });
    }
    let present = |path: &str| {
        archive
            .members()
            .iter()
            .any(|m| m.path == path && m.action == RestoreAction::Write)
    };
    check(
        &files,
        !present("etc/kvm/ssh_stop") || present("boot/start_ssh_once"),
    )
}

pub(super) async fn check_host_keys(
    archive: &mut ValidatedRestore,
    private_staging: &Path,
) -> Result<()> {
    use key_probe::Algorithm;
    for (index, path) in HOST_KEYS.iter().enumerate() {
        let private_index = archive.members().iter().position(|m| m.path == *path);
        let public_path = format!("{path}.pub");
        let public_index = archive.members().iter().position(|m| m.path == public_path);
        let Some(private_index) = private_index else {
            if public_index.is_some() {
                return Err(SshRestoreError::InvalidKey);
            }
            continue;
        };
        let member = &archive.members()[private_index];
        if member.action != RestoreAction::Write
            || member.size == 0
            || member.size > MAX_CONFIG as u64
        {
            return Err(SshRestoreError::InvalidKey);
        }
        let mut private = super::restore_capsule::create_private_spool(private_staging)
            .map_err(|_| SshRestoreError::ProbeRuntime)?;
        archive.copy_file(private_index, &mut private)?;
        let public = if let Some(public_index) = public_index {
            let member = &archive.members()[public_index];
            if member.action != RestoreAction::Write || member.size > key_probe::MAX_PUBLIC as u64 {
                return Err(SshRestoreError::InvalidKey);
            }
            let mut output = BoundedBytes {
                bytes: Zeroizing::new(Vec::with_capacity(member.size as usize)),
                limit: key_probe::MAX_PUBLIC,
            };
            archive.copy_file(public_index, &mut output)?;
            Some(output.bytes)
        } else {
            None
        };
        key_probe::check_pair(
            &private,
            public.as_deref().map(|b| b.as_slice()),
            [Algorithm::Rsa, Algorithm::Ecdsa, Algorithm::Ed25519][index],
            private_staging,
        )
        .await?;
    }
    Ok(())
}

fn is_config(path: &str) -> bool {
    path == MAIN || path.starts_with("etc/ssh/sshd_config.d/")
}

// Shared with the private syntax-root builder. Client private keys/config,
// enablement flags and arbitrary broader restore members are not runtime input.
pub(super) fn runtime_file(path: &str) -> bool {
    FILES.contains(&path) || path.starts_with("etc/ssh/sshd_config.d/")
}
fn file_limit(path: &str) -> usize {
    if is_config(path) || HOST_KEYS.contains(&path) {
        MAX_CONFIG
    } else {
        MAX_DATA
    }
}
fn check(files: &[File], enabled: bool) -> Result<()> {
    if !files.iter().any(|f| f.path == MAIN) {
        return Err(SshRestoreError::Invalid);
    }
    if enabled
        && !files
            .iter()
            .any(|f| HOST_KEYS.contains(&f.path.as_str()) && !f.bytes.is_empty())
    {
        return Err(SshRestoreError::Invalid);
    }
    let mut total = 0;
    for file in files.iter().filter(|f| is_config(&f.path)) {
        total += file.bytes.len();
        if total > MAX_CONFIG_TOTAL {
            return Err(SshRestoreError::Limit);
        }
        std::str::from_utf8(&file.bytes).map_err(|_| SshRestoreError::Invalid)?;
        for line in file.bytes.split(|b| *b == b'\n') {
            if let Some(line) = lexer::parse(line)? {
                check_line(&line, files)?;
            }
        }
    }
    Ok(())
}
fn only(line: &lexer::Line) -> Result<&str> {
    if line.len() != 1 {
        return Err(SshRestoreError::Invalid);
    }
    line.arg(0)
        .filter(|s| !s.is_empty())
        .ok_or(SshRestoreError::Invalid)
}
fn check_line(line: &lexer::Line, files: &[File]) -> Result<()> {
    use policy::Rule;
    let rule = policy::rule(&line.keyword).ok_or(SshRestoreError::Unsupported)?;
    if line.arg(0).is_none() {
        return Err(SshRestoreError::Invalid);
    }
    match rule {
        Rule::Scalar => {}
        Rule::Match => {
            let mut index = 0;
            while index < line.len() {
                let token = line.arg(index).ok_or(SshRestoreError::Invalid)?;
                if token.eq_ignore_ascii_case("all") {
                    if line.len() != 1 {
                        return Err(SshRestoreError::Invalid);
                    }
                    break;
                }
                if token.eq_ignore_ascii_case("invalid-user") {
                    index += 1;
                    continue;
                }
                let (criterion, inline) = token
                    .split_once('=')
                    .map(|(k, v)| (k, Some(v)))
                    .unwrap_or((token, None));
                if ![
                    "user",
                    "group",
                    "host",
                    "address",
                    "localaddress",
                    "localport",
                    "rdomain",
                    "version",
                ]
                .iter()
                .any(|c| criterion.eq_ignore_ascii_case(c))
                {
                    return Err(SshRestoreError::Unsupported);
                }
                let value = if let Some(value) = inline {
                    value
                } else {
                    index += 1;
                    line.arg(index).ok_or(SshRestoreError::Invalid)?
                };
                if value.is_empty() || value.starts_with('#') {
                    return Err(SshRestoreError::Invalid);
                }
                index += 1;
            }
        }
        Rule::Include => {
            for index in 0..line.len() {
                let pattern = line.arg(index).ok_or(SshRestoreError::Invalid)?;
                let relative = pattern.strip_prefix("/etc/ssh/").unwrap_or(pattern);
                let name = relative
                    .strip_prefix("sshd_config.d/")
                    .ok_or(SshRestoreError::Unsupported)?;
                if name.is_empty()
                    || !name.ends_with(".conf")
                    || name.starts_with('.')
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-*?[]!^".contains(&b))
                {
                    return Err(SshRestoreError::Unsupported);
                }
            }
        }
        Rule::HostKey => {
            let path = only(line)?;
            if !path.eq_ignore_ascii_case("none")
                && !HOST_KEYS.iter().any(|p| path == format!("/{p}"))
            {
                return Err(SshRestoreError::Unsupported);
            }
        }
        Rule::HostCertificate => {
            let path = only(line)?;
            if !path.eq_ignore_ascii_case("none")
                && ![
                    "/etc/ssh/ssh_host_rsa_key-cert.pub",
                    "/etc/ssh/ssh_host_ecdsa_key-cert.pub",
                    "/etc/ssh/ssh_host_ed25519_key-cert.pub",
                ]
                .contains(&path)
            {
                return Err(SshRestoreError::Unsupported);
            }
            require_file(path, files)?;
        }
        Rule::AuthorizedKeys => {
            for index in 0..line.len() {
                let path = line.arg(index).ok_or(SshRestoreError::Invalid)?;
                if path.eq_ignore_ascii_case("none") {
                    continue;
                }
                let suffix = [".ssh/authorized_keys", ".ssh/authorized_keys2"];
                if !suffix.iter().any(|s| {
                    path == *s
                        || path == format!("/root/{s}")
                        || path == format!("%h/{s}")
                        || path == format!("~/{s}")
                }) {
                    return Err(SshRestoreError::Unsupported);
                }
            }
        }
        Rule::Data => {
            for index in 0..line.len() {
                let path = line.arg(index).ok_or(SshRestoreError::Invalid)?;
                let expected = if line.keyword.eq_ignore_ascii_case(b"modulifile") {
                    "/etc/ssh/moduli"
                } else if line.keyword.eq_ignore_ascii_case(b"banner") {
                    "/etc/ssh/banner"
                } else if line.keyword.eq_ignore_ascii_case(b"trustedusercakeys") {
                    "/etc/ssh/trusted-user-ca-keys.pub"
                } else if line.keyword.eq_ignore_ascii_case(b"revokedkeys") {
                    "/etc/ssh/revoked_keys"
                } else {
                    "/etc/ssh/authorized_principals"
                };
                if !path.eq_ignore_ascii_case("none") && path != expected {
                    return Err(SshRestoreError::Unsupported);
                }
                require_file(path, files)?;
            }
        }
        Rule::Agent | Rule::DisabledHook | Rule::NoChroot => {
            if !only(line)?.eq_ignore_ascii_case("none") {
                return Err(SshRestoreError::Unsupported);
            }
        }
        Rule::Provider => {
            if only(line)? != "internal" {
                return Err(SshRestoreError::Unsupported);
            }
        }
        Rule::NoPam | Rule::DisabledEnvironment => {
            if !only(line)?.eq_ignore_ascii_case("no") {
                return Err(SshRestoreError::Unsupported);
            }
        }
        Rule::Pid => {
            if !["none", "/run/sshd.pid", "/var/run/sshd.pid"].contains(&only(line)?) {
                return Err(SshRestoreError::Unsupported);
            }
        }
        Rule::Session | Rule::Auth | Rule::Xauth => {
            let expected = match rule {
                Rule::Session => "/usr/libexec/sshd-session",
                Rule::Auth => "/usr/libexec/sshd-auth",
                _ => "/usr/bin/xauth",
            };
            if only(line)? != expected {
                return Err(SshRestoreError::Unsupported);
            }
        }
        Rule::Subsystem => {
            if line.len() < 2
                || line.arg(0) != Some("sftp")
                || ![Some("internal-sftp"), Some("/usr/libexec/sftp-server")].contains(&line.arg(1))
            {
                return Err(SshRestoreError::Unsupported);
            }
            safe_arguments(line, 2)?;
        }
        Rule::Force => {
            if !line.plain_command {
                return Err(SshRestoreError::Unsupported);
            }
            if line.len() == 1 && line.arg(0).is_some_and(|s| s.eq_ignore_ascii_case("none")) {
                return Ok(());
            }
            if line.arg(0) != Some("internal-sftp") {
                return Err(SshRestoreError::Unsupported);
            }
            safe_arguments(line, 1)?;
        }
    }
    Ok(())
}
fn safe_arguments(line: &lexer::Line, start: usize) -> Result<()> {
    for index in start..line.len() {
        let arg = line.arg(index).ok_or(SshRestoreError::Invalid)?;
        if arg.is_empty()
            || !arg
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-/,:@%+=".contains(&b))
        {
            return Err(SshRestoreError::Unsupported);
        }
    }
    Ok(())
}
fn require_file(path: &str, files: &[File]) -> Result<()> {
    if !path.eq_ignore_ascii_case("none")
        && !files
            .iter()
            .any(|f| path.strip_prefix('/') == Some(f.path.as_str()))
    {
        return Err(SshRestoreError::Invalid);
    }
    Ok(())
}
struct BoundedBytes {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}
impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "restore_ssh_tests.rs"]
mod tests;
