//! Bounded authenticated encryption for raw-update configuration transfer.
//!
//! The trusted restore secret belongs outside the data partition. This module
//! does not authorize transactions, prevent replay, parse tar or apply state:
//! those are separate responsibilities of the early-boot transaction helper.

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};

use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::stream::{DecryptorBE32, EncryptorBE32},
};
use rand_core::{OsRng, RngCore};
use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
use zeroize::{Zeroize, Zeroizing};

use super::restore_fs;
#[cfg(test)]
use std::fs;

const MAGIC: &[u8; 8] = b"NKCAP001";
const VERSION_BYTES: usize = 64;
const NONCE_BYTES: usize = 7;
const HEADER_BYTES: usize = 8 + 16 + 8 + 1 + VERSION_BYTES + NONCE_BYTES;
const TAG_BYTES: usize = 16;
pub const CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_PLAINTEXT_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CapsuleError {
    #[error("invalid restore capsule context")]
    InvalidContext,
    #[error("restore capsule does not match the trusted transaction")]
    HeaderMismatch,
    #[error("restore capsule authentication failed")]
    Authentication,
    #[error("restore capsule has unexpected trailing data")]
    TrailingData,
    #[error("restore staging must be a private owned directory on rootfs")]
    InvalidStaging,
    #[error("secure entropy is unavailable")]
    Entropy,
    #[error("restore capsule I/O failed: {0}")]
    Io(#[from] io::Error),
}

type Result<T> = std::result::Result<T, CapsuleError>;

// No Debug, Clone or general serialization. The ticket child module alone can
// encode the key into its fixed protected p1 record; never into a p3 capsule.
pub struct RestoreSecret {
    transaction_id: [u8; 16],
    target_version: String,
    plaintext_len: u64,
    key: Zeroizing<[u8; 32]>,
}

impl RestoreSecret {
    fn validate(&self) -> Result<()> {
        validate_context(&self.target_version, self.plaintext_len)?;
        if self.transaction_id == [0; 16] {
            return Err(CapsuleError::InvalidContext);
        }
        Ok(())
    }

    fn header(&self, nonce: &[u8; NONCE_BYTES]) -> [u8; HEADER_BYTES] {
        let mut header = [0; HEADER_BYTES];
        header[..8].copy_from_slice(MAGIC);
        header[8..24].copy_from_slice(&self.transaction_id);
        header[24..32].copy_from_slice(&self.plaintext_len.to_be_bytes());
        header[32] = self.target_version.len() as u8;
        header[33..33 + self.target_version.len()].copy_from_slice(self.target_version.as_bytes());
        header[HEADER_BYTES - NONCE_BYTES..].copy_from_slice(nonce);
        header
    }
}

/// Encrypt exactly `plaintext_len` bytes and return a fresh transaction secret.
///
/// The writer must be a private unpublished capsule file. On any error no
/// secret is returned, so partial output cannot become an authorized restore.
/// A new key/transaction/nonce is generated for every call; callers cannot reuse
/// a key to seal another stream through this interface.
pub fn prepare_capsule<R: Read, W: Write>(
    target_version: &str,
    plaintext_len: u64,
    plaintext: &mut R,
    output: &mut W,
) -> Result<RestoreSecret> {
    validate_context(target_version, plaintext_len)?;
    let mut secret = RestoreSecret {
        transaction_id: [0; 16],
        target_version: target_version.to_string(),
        plaintext_len,
        key: Zeroizing::new([0; 32]),
    };
    OsRng
        .try_fill_bytes(&mut secret.transaction_id)
        .map_err(|_| CapsuleError::Entropy)?;
    secret.validate()?;
    OsRng
        .try_fill_bytes(secret.key.as_mut())
        .map_err(|_| CapsuleError::Entropy)?;
    let mut nonce = [0; NONCE_BYTES];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| CapsuleError::Entropy)?;
    let header = secret.header(&nonce);
    let mut encryptor =
        EncryptorBE32::<ChaCha20Poly1305>::new((&*secret.key).into(), (&nonce).into());
    // One allocation per stream. AEAD appends a tag without growing capacity.
    let mut buffer = Zeroizing::new(Vec::with_capacity(CHUNK_BYTES + TAG_BYTES));
    output.write_all(&header)?;
    let mut remaining = plaintext_len;
    while remaining > CHUNK_BYTES as u64 {
        buffer.resize(CHUNK_BYTES, 0);
        plaintext.read_exact(&mut buffer)?;
        encryptor
            .encrypt_next_in_place(&header, &mut *buffer)
            .map_err(|_| CapsuleError::Authentication)?;
        output.write_all(&buffer)?;
        buffer.zeroize();
        remaining -= CHUNK_BYTES as u64;
    }
    buffer.resize(remaining as usize, 0);
    plaintext.read_exact(&mut buffer)?;
    require_eof(plaintext)?;
    encryptor
        .encrypt_last_in_place(&header, &mut *buffer)
        .map_err(|_| CapsuleError::Authentication)?;
    output.write_all(&buffer)?;
    output.flush()?;
    Ok(secret)
}

/// Read-only, fully authenticated plaintext held by an open private descriptor.
/// No path, mutable file or write operation is exposed to restore consumers.
/// The anonymous spool has no directory entry, even before the first write.
/// Closing the descriptor (including process termination) releases the spool; no pathname
/// with partial plaintext can survive a failed verification or crashed helper.
pub struct VerifiedPayload {
    file: File,
}

impl Read for VerifiedPayload {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

impl Seek for VerifiedPayload {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

/// Authenticate the entire capsule into a private rootfs spool before returning
/// any plaintext to a consumer. A late bad tag/truncation never yields a
/// VerifiedPayload and does not apply even the earlier authenticated chunks.
pub fn open_capsule<R: Read>(
    secret: &RestoreSecret,
    source: &mut R,
    private_root: &Path,
) -> Result<VerifiedPayload> {
    secret.validate()?;
    let mut header = [0; HEADER_BYTES];
    source.read_exact(&mut header)?;
    let mut nonce = [0; NONCE_BYTES];
    nonce.copy_from_slice(&header[HEADER_BYTES - NONCE_BYTES..]);
    // Use length/version/transaction from the trusted secret, not from a p3
    // header. Compare before allocating a spool or reading any body bytes.
    if header != secret.header(&nonce) {
        return Err(CapsuleError::HeaderMismatch);
    }
    let file = create_private_spool(private_root)?;
    let mut spool = VerifiedPayload { file };
    let mut decryptor =
        DecryptorBE32::<ChaCha20Poly1305>::new((&*secret.key).into(), (&nonce).into());
    let mut buffer = Zeroizing::new(Vec::with_capacity(CHUNK_BYTES + TAG_BYTES));
    let mut remaining = secret.plaintext_len;
    while remaining > CHUNK_BYTES as u64 {
        buffer.resize(CHUNK_BYTES + TAG_BYTES, 0);
        source.read_exact(&mut buffer)?;
        decryptor
            .decrypt_next_in_place(&header, &mut *buffer)
            .map_err(|_| CapsuleError::Authentication)?;
        spool.file.write_all(&buffer)?;
        buffer.zeroize();
        remaining -= CHUNK_BYTES as u64;
    }
    buffer.resize(remaining as usize + TAG_BYTES, 0);
    source.read_exact(&mut buffer)?;
    decryptor
        .decrypt_last_in_place(&header, &mut *buffer)
        .map_err(|_| CapsuleError::Authentication)?;
    require_eof(source)?;
    spool.file.write_all(&buffer)?;
    spool.file.sync_all()?;
    spool.file.seek(SeekFrom::Start(0))?;
    Ok(spool)
}

// Shared with archive capture: a private, unlinked rootfs descriptor is the
// only permitted staging medium for plaintext restoration material.
pub(super) fn create_private_spool(private_root: &Path) -> Result<File> {
    let directory = check_private_root(private_root)?;
    // O_TMPFILE never creates a directory entry, including the interval before
    // a possible crash or I/O error. EXCL also prevents later linking of the fd.
    // Unsupported kernels/filesystems fail closed; do not fall back to a named
    // plaintext file or to /data/tmpfs.
    let file: File = openat2(
        &directory,
        ".",
        OFlags::RDWR | OFlags::TMPFILE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
        ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(io::Error::from)?
    .into();
    Ok(file)
}

fn require_eof<R: Read>(source: &mut R) -> Result<()> {
    let mut byte = [0];
    loop {
        match source.read(&mut byte) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(CapsuleError::TrailingData),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err.into()),
        }
    }
}

fn validate_context(version: &str, length: u64) -> Result<()> {
    if version.is_empty()
        || version.len() > VERSION_BYTES
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        || length == 0
        || length > MAX_PLAINTEXT_BYTES
    {
        return Err(CapsuleError::InvalidContext);
    }
    Ok(())
}

fn check_private_root(root: &Path) -> Result<File> {
    let directory = restore_fs::open_root(root, true).map_err(|err| {
        if err.kind() == io::ErrorKind::InvalidInput
            || matches!(
                err.raw_os_error(),
                Some(nix::libc::ELOOP | nix::libc::EXDEV | nix::libc::ENOTDIR)
            )
        {
            CapsuleError::InvalidStaging
        } else {
            err.into()
        }
    })?;
    let metadata = directory.metadata()?;
    if metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
        || metadata.dev() != File::open("/")?.metadata()?.dev()
    {
        return Err(CapsuleError::InvalidStaging);
    }
    Ok(directory)
}

#[path = "restore_ticket.rs"]
pub mod ticket;

#[cfg(test)]
#[path = "restore_capsule_tests.rs"]
mod tests;
