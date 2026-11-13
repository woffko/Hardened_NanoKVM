//! Shared lexical home selection, not filesystem trust or launch authorization.
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    io,
    path::{Component, Path, PathBuf},
};

const DEFAULT: &str = "/root/.picoclaw";
const MAX_BYTES: usize = 4095;
/// Fixed fresh scratch, never an alternative runtime home selected by a client.
pub const ONBOARD_DIRECTORY: &str = ".nanokvm-onboard";

/// Immutable launch configuration, not filesystem trust or a writer capability.
/// The containing Group retains this value through drain, trial and rollback.
#[derive(Debug)]
pub struct Home {
    path: PathBuf,
    fingerprint: [u8; 32],
}

impl Default for Home {
    fn default() -> Self {
        Self::selected(PathBuf::from(DEFAULT))
    }
}

impl Home {
    pub fn resolve() -> io::Result<Self> {
        resolve().map(Self::selected)
    }

    fn selected(path: PathBuf) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"NanoKVM PicoClaw effective home v1\0");
        hash.update(path.as_os_str().as_encoded_bytes());
        Self {
            path,
            fingerprint: hash.finalize().into(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    #[cfg(test)]
    pub(super) fn fixture(value: &str, cwd: &str) -> Self {
        Self::selected(resolve_from(Some(OsStr::new(value)), Path::new(cwd)).unwrap())
    }
}

/// Resolve before changing cwd. HOME/passwd do not select a second service home.
/// The caller still needs checked rootfs I/O, pair settlement and writer/native
/// admission; an absolute pathname alone supplies none of those capabilities.
pub fn resolve() -> io::Result<PathBuf> {
    resolve_with(
        std::env::var_os("PICOCLAW_HOME").as_deref(),
        std::env::current_dir,
    )
}

fn resolve_with(
    value: Option<&OsStr>,
    cwd: impl FnOnce() -> io::Result<PathBuf>,
) -> io::Result<PathBuf> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid picoclaw home");
    let value = match value {
        Some(value) => {
            let value = value.to_str().ok_or_else(invalid)?;
            if value.trim().is_empty() {
                DEFAULT
            } else {
                value
            }
        }
        None => DEFAULT,
    };
    let selected = Path::new(value);
    let absolute = if selected.is_absolute() {
        selected.to_path_buf()
    } else {
        let cwd = cwd()?;
        if !cwd.is_absolute() {
            return Err(invalid());
        }
        cwd.join(selected)
    };
    let mut normalized = PathBuf::from("/");
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => normalized.push(name),
            _ => return Err(invalid()),
        }
    }
    let text = normalized.to_str().ok_or_else(invalid)?;
    if text.len() > MAX_BYTES || text.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(invalid());
    }
    Ok(normalized)
}

#[cfg(test)]
fn resolve_from(value: Option<&OsStr>, cwd: &Path) -> io::Result<PathBuf> {
    // Inject a private fixture cwd without mutating global process state.
    resolve_with(value, || Ok(cwd.to_path_buf()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn frozen_absolute_or_default_selection_does_not_depend_on_a_later_cwd() {
        for value in [
            None,
            Some(OsStr::new("/private/custom")),
            Some(OsStr::new(" ")),
        ] {
            assert!(resolve_with(value, || Err(io::ErrorKind::NotFound.into())).is_ok());
        }
        assert_eq!(
            resolve_with(Some(OsStr::new("relative")), || Err(
                io::ErrorKind::NotFound.into()
            ))
            .unwrap_err()
            .kind(),
            io::ErrorKind::NotFound
        );
        let home = Home::fixture("relative", "/original");
        assert_eq!(home.path(), Path::new("/original/relative"));
        assert_eq!(
            home.fingerprint(),
            Home::fixture("/original/relative", "/other").fingerprint()
        );
        assert_ne!(
            home.fingerprint(),
            Home::fixture("relative", "/other").fingerprint()
        );
    }

    #[test]
    fn home_selection_is_explicit_and_absolute_before_chdir() {
        for value in [None, Some(OsStr::new("")), Some(OsStr::new(" \t\u{2003}"))] {
            assert_eq!(
                resolve_from(value, Path::new("/elsewhere")).unwrap(),
                Path::new(DEFAULT)
            );
        }
        for (value, expected) in [
            ("relative/./home", "/original/relative/home"),
            ("/custom//./home", "/custom/home"),
            (" space ", "/original/ space "),
            ("/данные/agent", "/данные/agent"),
        ] {
            assert_eq!(
                resolve_from(Some(OsStr::new(value)), Path::new("/original")).unwrap(),
                Path::new(expected)
            );
        }
    }

    #[test]
    fn unsafe_or_unrepresentable_home_never_falls_back() {
        for value in [
            "../other",
            "/root/../other",
            "/bad\nname",
            "/bad\rname",
            "/bad\tname",
        ] {
            assert_eq!(
                resolve_from(Some(OsStr::new(value)), Path::new("/original"))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert!(
            resolve_from(Some(OsStr::from_bytes(b"/bad\xff")), Path::new("/original")).is_err()
        );
        assert!(
            resolve_from(
                Some(OsStr::new(&"x".repeat(MAX_BYTES))),
                Path::new("/original")
            )
            .is_err()
        );
        assert!(resolve_from(Some(OsStr::new("relative")), Path::new("relative-cwd")).is_err());
    }
}
