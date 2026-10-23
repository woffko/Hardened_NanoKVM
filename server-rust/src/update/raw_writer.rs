//! The raw writer's core: copy a verified image onto its partition and prove
//! that the partition now holds exactly those bytes. Stopping the system,
//! publishing the ticket on the new boot partition and the reboot belong to
//! the writer process.

use rustix::fs::{Advice, SeekFrom, fadvise, seek};
use sha2::{Digest, Sha256};
use std::{fs::File, io, num::NonZeroU64, os::unix::fs::FileExt};

const CHUNK: usize = 1024 * 1024;

#[cfg(test)]
thread_local! {
    /// Runs after the sync, before the read-back, to change the medium.
    static AFTER_SYNC: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}

#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error("raw image write I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("the target partition is smaller than the image")]
    TooSmall,
    #[error("the partition does not read back as the verified image")]
    Mismatch,
}
type Result<T> = std::result::Result<T, WriteError>;

/// Copies `size` bytes of `image` to the start of `device` in 1 MiB chunks,
/// syncs them, drops the cached pages and reads the range back from the
/// medium; the result must hash to `sha256`, the authenticated image digest.
/// `image` is the immutable verified snapshot; nothing here undoes a write.
pub fn write_image(image: &File, device: &File, size: u64, sha256: &[u8; 32]) -> Result<()> {
    if seek(device, SeekFrom::End(0)).map_err(io::Error::from)? < size {
        return Err(WriteError::TooSmall);
    }
    let mut buffer = vec![0; CHUNK];
    let mut offset = 0;
    while offset < size {
        let chunk = &mut buffer[..CHUNK.min((size - offset) as usize)];
        image.read_exact_at(chunk, offset)?;
        device.write_all_at(chunk, offset)?;
        offset += chunk.len() as u64;
    }
    device.sync_data()?;
    #[cfg(test)]
    AFTER_SYNC.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook()
        }
    });
    if let Some(length) = NonZeroU64::new(size) {
        fadvise(device, 0, Some(length), Advice::DontNeed).map_err(io::Error::from)?;
    }
    let mut hash = Sha256::new();
    offset = 0;
    while offset < size {
        let chunk = &mut buffer[..CHUNK.min((size - offset) as usize)];
        device.read_exact_at(chunk, offset)?;
        hash.update(&*chunk);
        offset += chunk.len() as u64;
    }
    if <[u8; 32]>::from(hash.finalize()) != *sha256 {
        return Err(WriteError::Mismatch);
    }
    Ok(())
}

#[cfg(test)]
#[path = "raw_writer_tests.rs"]
mod tests;
