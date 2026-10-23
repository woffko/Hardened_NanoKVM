//! The raw writer's core: copy a verified image onto its partition, prove that
//! the partition now holds exactly those bytes, and order the whole write so
//! that every undoable step comes first. The device operations and the reboot
//! belong to the writer process.

use super::restore_capsule::ticket::{RestoreTicket, TicketError};
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

/// The two partitions a raw update writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Partition {
    Boot,
    Rootfs,
}

/// The device operations of a raw write, in the order `run_writer` uses them.
/// The device implementation lives in the writer process; tests use a fake.
pub trait WriterSystem {
    /// Stops every process except PID 1 and the writer itself.
    fn stop_others(&mut self) -> io::Result<()>;
    /// Flushes and remounts the root filesystem read-only.
    fn freeze_root(&mut self) -> io::Result<()>;
    /// Unmounts the old boot partition.
    fn release_boot(&mut self) -> io::Result<()>;
    fn open_partition(&mut self, partition: Partition) -> io::Result<File>;
    /// Mounts the newly written boot partition privately and publishes the
    /// prepared ticket there.
    fn publish_ticket(&mut self, ticket: &RestoreTicket) -> std::result::Result<(), TicketError>;
    fn log(&mut self, line: &str);
}

/// What to write, all from the authenticated manifest and the prepared ticket.
pub struct WritePlan<'a> {
    /// BOOT, ROOTFS: the immutable verified image snapshots.
    pub images: [&'a File; 2],
    pub sizes: [u64; 2],
    pub sha256: [[u8; 32]; 2],
    pub ticket: &'a RestoreTicket,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Both partitions read back as their images and the ticket is published
    /// on the new boot partition.
    Written,
    /// Nothing was written: the old system is intact and a reboot restores it.
    NotStarted,
    /// A partition write started and did not complete: recovery is manual.
    Failed,
}

/// One step before the first partition write.
type Step<S> = fn(&mut S) -> io::Result<()>;

/// Runs the raw write. Every step that can still be undone by a reboot comes
/// before the first partition write: stopping the system, the read-only root
/// and releasing the old boot partition. ROOTFS is written before BOOT, and
/// the ticket is published last, so a failure never leaves a ticket beside a
/// partly written system. The caller reboots after any outcome.
pub fn run_writer<S: WriterSystem>(system: &mut S, plan: &WritePlan<'_>) -> Outcome {
    let steps: [(&str, Step<S>); 3] = [
        ("stop services", S::stop_others),
        ("read-only root", S::freeze_root),
        ("release boot", S::release_boot),
    ];
    // One at a time: a failed step must not let the next one run.
    for (step, run) in steps {
        if let Err(error) = run(system) {
            system.log(&format!("raw write not started: {step} failed: {error}"));
            return Outcome::NotStarted;
        }
    }
    for (index, partition) in [(1, Partition::Rootfs), (0, Partition::Boot)] {
        let device = match system.open_partition(partition) {
            Ok(device) => device,
            Err(error) if partition == Partition::Rootfs => {
                system.log(&format!(
                    "raw write not started: open {partition:?} failed: {error}"
                ));
                return Outcome::NotStarted;
            }
            Err(error) => {
                system.log(&format!(
                    "raw write failed: open {partition:?} failed: {error}"
                ));
                return Outcome::Failed;
            }
        };
        if let Err(error) = write_image(
            plan.images[index],
            &device,
            plan.sizes[index],
            &plan.sha256[index],
        ) {
            system.log(&format!("raw write failed: {partition:?}: {error}"));
            return Outcome::Failed;
        }
        system.log(&format!("raw write: {partition:?} written and verified"));
    }
    if let Err(error) = system.publish_ticket(plan.ticket) {
        system.log(&format!(
            "raw write failed: restore ticket not published: {error}"
        ));
        return Outcome::Failed;
    }
    system.log("raw write complete");
    Outcome::Written
}

#[path = "raw_writer_device.rs"]
pub mod device;

#[cfg(test)]
#[path = "raw_writer_tests.rs"]
mod tests;
