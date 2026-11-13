//! Descriptor-bound PUBLIC signature inputs. No named temporary files, inherited
//! writable aliases, trust fallback or protection against hostile local root.

use super::{
    LEGACY_TEST_UPDATE_KEY_ID, LEGACY_UPDATE_KEY_ID, MAX_UPDATE_KEY_POLICY_BYTES,
    MAX_UPDATE_PUBLIC_KEY_BYTES, UPDATE_KEY_POLICY_FILE, UPDATE_KEYRING_DIR,
    UPDATE_PUBLIC_KEY_SUFFIX, parse_update_key_policy, validate_update_key_id,
};
use crate::{
    AppError, Result,
    system::command::{AllowedCommand, run_allowed_owned},
    update::{
        restore_fs,
        staged_metadata::{MAX_METADATA, MAX_SIGNATURE},
        staged_snapshot::reopen_readonly,
    },
};
use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
use std::{
    fs::{self, File},
    io::{self, ErrorKind, Read, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Component, Path},
    process,
    time::Duration,
};

/// Files stay owned by the command supervisor through pipe cleanup/child reap.
/// /proc/PARENT/fd paths deliberately refer to these exact descriptions, not
/// configurable source names or descriptor numbers inherited by the child.
struct SignatureInputs {
    key: File,
    metadata: File,
    signature: File,
}

pub(crate) async fn verify_metadata_signature(
    metadata: &[u8],
    signature: &[u8],
    configured_key: &Path,
    key_id: &str,
    timeout: Duration,
) -> Result<()> {
    if metadata.is_empty()
        || metadata.len() > MAX_METADATA
        || signature.is_empty()
        || signature.len() > MAX_SIGNATURE
    {
        return Err(AppError::BadRequest(
            "invalid signed metadata input size".into(),
        ));
    }
    validate_update_key_id(key_id)?;
    let metadata = metadata.to_vec();
    let signature = signature.to_vec();
    let configured_key = configured_key.to_path_buf();
    let key_id = key_id.to_owned();
    let inputs = tokio::task::spawn_blocking(move || {
        SignatureInputs::capture(&metadata, &signature, &configured_key, &key_id)
    })
    .await
    .map_err(|_| AppError::Internal("signature input capture task failed".into()))??;
    inputs.verify(timeout).await
}

impl SignatureInputs {
    fn capture(metadata: &[u8], signature: &[u8], configured: &Path, key_id: &str) -> Result<Self> {
        let parent = configured.parent().ok_or_else(unsafe_trust)?;
        let name = configured
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(unsafe_trust)?;
        let root = open_trust_root(parent)?;
        // Every full start installs the policy before a request is served, so
        // a missing one is damage, not a device that predates policies. Without
        // it every key ID would be allowed, the retired ones included.
        let policy =
            PinnedTrustFile::open(&root, UPDATE_KEY_POLICY_FILE, MAX_UPDATE_KEY_POLICY_BYTES)?
                .ok_or_else(|| {
                    AppError::Config(
                        "the update key policy is missing; restart the device to restore it".into(),
                    )
                })?;
        let bytes = policy.read(&root, UPDATE_KEY_POLICY_FILE)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| unsafe_trust())?;
        if !parse_update_key_policy(text)?.contains(key_id) {
            return Err(AppError::BadRequest(
                "update signature key id is not allowed by policy".into(),
            ));
        }
        let (key_root, key_name) =
            if matches!(key_id, LEGACY_UPDATE_KEY_ID | LEGACY_TEST_UPDATE_KEY_ID) {
                (root.try_clone()?, name.to_owned())
            } else {
                let directory = restore_fs::open_beneath(
                    &root,
                    UPDATE_KEYRING_DIR,
                    OFlags::RDONLY | OFlags::DIRECTORY,
                )?;
                check_directory(&directory.metadata()?, true)?;
                (directory, format!("{key_id}{UPDATE_PUBLIC_KEY_SUFFIX}"))
            };
        let pinned = PinnedTrustFile::open(&key_root, &key_name, MAX_UPDATE_PUBLIC_KEY_BYTES)?
            .ok_or_else(|| AppError::Config("update public key is unavailable".into()))?;
        let key = pinned.read(&key_root, &key_name)?;
        // Detect a cooperating policy publication/replacement during capture.
        // Final installation still requires the separately held writer freeze.
        policy.check_named(&root, UPDATE_KEY_POLICY_FILE)?;
        Ok(Self {
            key: anonymous_readonly(&root, &key)?,
            metadata: anonymous_readonly(&root, metadata)?,
            signature: anonymous_readonly(&root, signature)?,
        })
    }

    async fn verify(self, timeout: Duration) -> Result<()> {
        let arguments = [
            "dgst".to_owned(),
            "-sha256".to_owned(),
            "-verify".to_owned(),
            proc_path(&self.key),
            "-signature".to_owned(),
            proc_path(&self.signature),
            proc_path(&self.metadata),
        ];
        let output = run_allowed_owned(AllowedCommand::OpenSsl, arguments, timeout, self).await?;
        if output.status != 0 {
            return Err(AppError::BadRequest(
                "update metadata signature verification failed".into(),
            ));
        }
        Ok(())
    }
}

fn proc_path(file: &File) -> String {
    format!("/proc/{}/fd/{}", process::id(), file.as_raw_fd())
}

fn open_trust_root(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        return Err(unsafe_trust());
    }
    let mut directory = File::open("/")?;
    check_directory(&directory.metadata()?, false)?;
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let name = name.to_str().ok_or_else(unsafe_trust)?;
                directory =
                    restore_fs::open_beneath(&directory, name, OFlags::RDONLY | OFlags::DIRECTORY)?;
                check_directory(&directory.metadata()?, components.peek().is_none())?;
            }
            _ => return Err(unsafe_trust()),
        }
    }
    check_directory(&directory.metadata()?, true)?;
    Ok(directory)
}

fn check_directory(metadata: &fs::Metadata, leaf: bool) -> Result<()> {
    let uid = nix::unistd::geteuid().as_raw();
    let mode = metadata.mode();
    // A root-owned sticky shared ANCESTOR may contain a protected user/root
    // directory (e.g. host fixtures in /tmp). Sticky protection plus ownership
    // checks on every child forbids an untrusted user from renaming the chain.
    // The trust root/keyring themselves are never shared/sticky. NO_XDEV also
    // refuses target tmpfs/media/configured mount crossings, without fallback.
    let shared_ancestor = !leaf && metadata.uid() == 0 && mode & 0o1000 != 0;
    if !metadata.is_dir()
        || (metadata.uid() != 0 && metadata.uid() != uid)
        || (leaf && metadata.uid() != uid)
        || mode & 0o6000 != 0
        || (mode & 0o1022 != 0 && !shared_ancestor)
    {
        return Err(unsafe_trust());
    }
    Ok(())
}

struct PinnedTrustFile {
    identity: File,
    metadata: fs::Metadata,
}

impl PinnedTrustFile {
    fn open(parent: &File, name: &str, maximum: u64) -> Result<Option<Self>> {
        let identity = match restore_fs::open_beneath(parent, name, OFlags::PATH) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let metadata = identity.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.mode() & 0o7022 != 0
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > maximum
        {
            return Err(unsafe_trust());
        }
        Ok(Some(Self { identity, metadata }))
    }

    fn read(&self, parent: &File, name: &str) -> Result<Vec<u8>> {
        let file = restore_fs::open_beneath(parent, name, OFlags::RDONLY | OFlags::NONBLOCK)?;
        self.check(&file.metadata()?)?;
        let mut bytes = Vec::with_capacity(self.metadata.len() as usize);
        file.take(self.metadata.len() + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != self.metadata.len() {
            return Err(unsafe_trust());
        }
        self.check_named(parent, name)?;
        Ok(bytes)
    }

    fn check_named(&self, parent: &File, name: &str) -> Result<()> {
        self.check(&self.identity.metadata()?)?;
        let named = restore_fs::open_beneath(parent, name, OFlags::PATH)?;
        self.check(&named.metadata()?)
    }

    fn check(&self, actual: &fs::Metadata) -> Result<()> {
        let expected = &self.metadata;
        if actual.dev() != expected.dev()
            || actual.ino() != expected.ino()
            || actual.uid() != expected.uid()
            || actual.mode() != expected.mode()
            || actual.nlink() != expected.nlink()
            || actual.len() != expected.len()
            || actual.mtime() != expected.mtime()
            || actual.mtime_nsec() != expected.mtime_nsec()
            || actual.ctime() != expected.ctime()
            || actual.ctime_nsec() != expected.ctime_nsec()
        {
            return Err(unsafe_trust());
        }
        Ok(())
    }
}

fn anonymous_readonly(root: &File, bytes: &[u8]) -> Result<File> {
    let mut writable: File = openat2(
        root,
        ".",
        OFlags::RDWR | OFlags::TMPFILE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(io::Error::from)?
    .into();
    writable.write_all(bytes)?;
    writable.sync_all()?;
    let readonly = reopen_readonly(&writable, bytes.len() as u64)
        .map_err(|_| AppError::Config("signature input snapshot is not protected".into()))?;
    drop(writable);
    Ok(readonly)
}

fn unsafe_trust() -> AppError {
    AppError::Config("update trust requires bounded, protected rootfs files and directories".into())
}

#[cfg(test)]
#[path = "trust_snapshot_tests.rs"]
mod tests;
