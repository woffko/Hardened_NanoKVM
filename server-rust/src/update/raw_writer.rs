//! The raw writer's core: copy a verified image onto its partition, prove that
//! the partition now holds exactly those bytes, and order the whole write so
//! that every undoable step comes first. The device operations and the reboot
//! belong to the writer process.

use super::{
    raw_transport::{ImageReceiver, TransferContext},
    restore_capsule::ticket::{Phase, RestoreTicket, Store, TicketError},
};
use rustix::fs::{Advice, SealFlags, SeekFrom, fadvise, fcntl_get_seals, seek};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io,
    num::NonZeroU64,
    os::{fd::AsRawFd, unix::fs::FileExt},
};

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

/// The writer mode's arguments, which the broker passes when it re-executes
/// its own sealed in-memory copy: the transfer context of the two images and
/// their authenticated digests.
pub struct WriterArguments {
    context: TransferContext,
    transaction: [u8; 16],
    version: String,
    sizes: [u64; 2],
    sha256: [[u8; 32]; 2],
}

impl WriterArguments {
    pub fn new(
        transaction: [u8; 16],
        version: &str,
        sizes: [u64; 2],
        sha256: [[u8; 32]; 2],
    ) -> Option<Self> {
        Some(Self {
            context: TransferContext::new(transaction, version, sizes).ok()?,
            transaction,
            version: version.to_string(),
            sizes,
            sha256,
        })
    }

    /// The arguments after `--raw-writer`, in the order the writer parses them.
    pub fn to_args(&self) -> Vec<OsString> {
        [
            ("--transaction", hex(&self.transaction)),
            ("--version", self.version.clone()),
            ("--boot-size", self.sizes[0].to_string()),
            ("--rootfs-size", self.sizes[1].to_string()),
            ("--boot-sha256", hex(&self.sha256[0])),
            ("--rootfs-sha256", hex(&self.sha256[1])),
        ]
        .into_iter()
        .flat_map(|(flag, value)| [OsString::from(flag), OsString::from(value)])
        .collect()
    }
}

/// Exactly the arguments `WriterArguments::to_args` produces.
pub fn parse_writer_arguments(args: &[OsString]) -> Option<WriterArguments> {
    if args.len() != 12 {
        return None;
    }
    let value = |index: usize, flag: &str| {
        (args[index] == flag)
            .then(|| args[index + 1].to_str())
            .flatten()
    };
    let size = |index, flag| value(index, flag)?.parse::<u64>().ok();
    WriterArguments::new(
        unhex(value(0, "--transaction")?)?,
        value(2, "--version")?,
        [size(4, "--boot-size")?, size(6, "--rootfs-size")?],
        [
            unhex(value(8, "--boot-sha256")?)?,
            unhex(value(10, "--rootfs-sha256")?)?,
        ],
    )
}

/// The writer process. It returns only when it refuses before touching
/// anything: run from a shell (not root, or not the sealed in-memory copy the
/// broker executes). Once it runs as that copy the broker has already stopped
/// the system, so every outcome ends in a reboot.
pub fn run_device_writer(arguments: WriterArguments) -> io::Error {
    if !nix::unistd::geteuid().is_root() {
        return io::Error::other("the raw writer must run as root");
    }
    if let Err(error) = File::open("/proc/self/exe").and_then(|exe| require_sealed(&exe)) {
        return error;
    }
    let mut system = device::DeviceSystem::new();
    match receive_inputs(&arguments) {
        Ok((boot, rootfs, ticket)) => {
            quiet_stderr();
            let outcome = run_writer(
                &mut system,
                &WritePlan {
                    images: [&boot, &rootfs],
                    sizes: arguments.sizes,
                    sha256: arguments.sha256,
                    ticket: &ticket,
                },
            );
            system.log(&format!("raw writer finished: {outcome:?}; rebooting"));
        }
        Err(error) => system.log(&format!("raw write not started: {error}; rebooting")),
    }
    nix::unistd::sync();
    reboot()
}

/// The images from the inherited socket on stdin, and the prepared ticket of
/// this transaction from the current boot partition. The store, and with it
/// its descriptor on /boot, is closed before the writer releases /boot.
fn receive_inputs(arguments: &WriterArguments) -> io::Result<(File, File, RestoreTicket)> {
    let socket = rustix::io::fcntl_dupfd_cloexec(io::stdin(), 3)?;
    let null = File::open("/dev/null")?;
    nix::unistd::dup2(null.as_raw_fd(), 0)?;
    let receiver = ImageReceiver::adopt(socket, std::process::id()).map_err(io::Error::other)?;
    let [boot, rootfs] = receiver
        .receive(&arguments.context)
        .map_err(io::Error::other)?;
    let ticket = Store::open_boot()
        .and_then(|mut store| store.load())
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other("the boot partition holds no restore ticket"))?;
    if ticket.phase() != Phase::Prepared
        || ticket.transaction_id() != arguments.transaction
        || ticket.image_digests() != arguments.sha256
    {
        return Err(io::Error::other(
            "the boot partition's ticket is not this transaction's prepared ticket",
        ));
    }
    Ok((boot.into_file(), rootfs.into_file(), ticket))
}

/// A memfd with every seal that keeps its bytes fixed.
fn require_sealed(file: &File) -> io::Result<()> {
    let required = SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE;
    match fcntl_get_seals(file) {
        Ok(seals) if seals.contains(required) => Ok(()),
        _ => Err(io::Error::other(
            "the raw writer runs only from the broker's sealed in-memory copy",
        )),
    }
}

/// stderr may be a log file on the root filesystem that is about to be
/// overwritten.
fn quiet_stderr() {
    if let Ok(null) = OpenOptions::new().write(true).open("/dev/null") {
        let _ = nix::unistd::dup2(null.as_raw_fd(), 2);
    }
}

fn reboot() -> ! {
    // SAFETY: reboot(2) with a command constant reads no caller memory.
    unsafe { nix::libc::reboot(nix::libc::LINUX_REBOOT_CMD_RESTART) };
    let _ = fs::write("/proc/sysrq-trigger", b"b");
    std::process::exit(70)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let digits = text.as_bytes();
    if digits.len() != 2 * N {
        return None;
    }
    let mut out = [0; N];
    for (byte, pair) in out.iter_mut().zip(digits.as_chunks::<2>().0) {
        let nibble = |digit: u8| {
            (digit as char)
                .to_digit(16)
                .filter(|_| !digit.is_ascii_uppercase())
        };
        *byte = (nibble(pair[0])? * 16 + nibble(pair[1])?) as u8;
    }
    Some(out)
}

#[path = "raw_writer_device.rs"]
pub mod device;

#[cfg(test)]
#[path = "raw_writer_tests.rs"]
mod tests;
