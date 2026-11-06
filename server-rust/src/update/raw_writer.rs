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
    path::Path,
};

const CHUNK: usize = 1024 * 1024;
/// Holds the superblock of the ROOTFS image, at 1 KiB.
const ROOT_HEADER: usize = 4096;
const DROP_CACHES: &str = "/proc/sys/vm/drop_caches";

#[cfg(test)]
thread_local! {
    /// Runs after the sync, before the read-back, to change the medium.
    static AFTER_SYNC: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
    /// Runs when all but the held first bytes are on the medium.
    static BEFORE_HEADER: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
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

/// How a partition's cached pages left memory before its read-back. The hash
/// is what decides; this says how much it proves, so the journal records it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Eviction {
    Advised,
    DropCaches,
    Nothing,
}

impl std::fmt::Display for Eviction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Advised => "fadvise",
            Self::DropCaches => "drop_caches",
            Self::Nothing => "no cache eviction",
        })
    }
}

/// Copies `size` bytes of `image` to the start of `device` in 1 MiB chunks,
/// syncs them, advises cache eviction when supported, and reads the entire
/// partition range back; it must hash to the authenticated image digest.
/// `image` is the immutable verified snapshot; nothing here undoes a write.
pub fn write_image(image: &File, device: &File, size: u64, sha256: &[u8; 32]) -> Result<Eviction> {
    write_image_with_advice(image, device, size, sha256, 0, evict_cache)
}

/// `write_image` for a root: its first bytes, superblock included, are zero
/// while the rest goes in and are written last. The kernel mounts the partition
/// only once all of it is there, however the write ends.
pub fn write_root(image: &File, device: &File, size: u64, sha256: &[u8; 32]) -> Result<Eviction> {
    write_image_with_advice(image, device, size, sha256, ROOT_HEADER, evict_cache)
}

fn fits(device: &File, size: u64) -> Result<()> {
    if seek(device, SeekFrom::End(0)).map_err(io::Error::from)? < size {
        return Err(WriteError::TooSmall);
    }
    Ok(())
}

/// The read-back has to come from the medium. Deployed kernels have no fadvise
/// (CONFIG_ADVISE_SYSCALLS=n), and this process is the only one left running.
fn evict_cache(device: &File, length: NonZeroU64) -> rustix::io::Result<Eviction> {
    match fadvise(device, 0, Some(length), Advice::DontNeed) {
        Ok(()) => Ok(Eviction::Advised),
        Err(rustix::io::Errno::NOSYS) => Ok(drop_caches(Path::new(DROP_CACHES))),
        Err(error) => Err(error),
    }
}

/// A refused knob is no reason to fail a good write: the hash still runs.
fn drop_caches(knob: &Path) -> Eviction {
    match fs::write(knob, "1\n") {
        Ok(()) => Eviction::DropCaches,
        Err(_) => Eviction::Nothing,
    }
}

fn hash_of(file: &File, size: u64) -> Result<[u8; 32]> {
    let mut buffer = vec![0; CHUNK];
    let mut hash = Sha256::new();
    let mut offset = 0;
    while offset < size {
        let chunk = &mut buffer[..CHUNK.min((size - offset) as usize)];
        file.read_exact_at(chunk, offset)?;
        hash.update(&*chunk);
        offset += chunk.len() as u64;
    }
    Ok(hash.finalize().into())
}

fn write_image_with_advice(
    image: &File,
    device: &File,
    size: u64,
    sha256: &[u8; 32],
    held: usize,
    advise: impl FnOnce(&File, NonZeroU64) -> rustix::io::Result<Eviction>,
) -> Result<Eviction> {
    fits(device, size)?;
    let held = held.min(size as usize);
    device.write_all_at(&vec![0; held], 0)?;
    device.sync_data()?;
    let mut buffer = vec![0; CHUNK];
    let mut offset = held as u64;
    while offset < size {
        let chunk = &mut buffer[..CHUNK.min((size - offset) as usize)];
        image.read_exact_at(chunk, offset)?;
        device.write_all_at(chunk, offset)?;
        offset += chunk.len() as u64;
    }
    device.sync_data()?;
    #[cfg(test)]
    BEFORE_HEADER.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook()
        }
    });
    let mut header = vec![0; held];
    image.read_exact_at(&mut header, 0)?;
    device.write_all_at(&header, 0)?;
    device.sync_data()?;
    #[cfg(test)]
    AFTER_SYNC.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook()
        }
    });
    let mut eviction = Eviction::Nothing;
    if let Some(length) = NonZeroU64::new(size) {
        match advise(device, length) {
            // DONTNEED is an advisory hint, not a durability barrier. The
            // completed sync_data above and full hash read-back below remain
            // mandatory even when the kernel has no advisory syscall.
            Ok(done) => eviction = done,
            Err(rustix::io::Errno::NOSYS) => {}
            Err(error) => return Err(io::Error::from(error).into()),
        }
    }
    if hash_of(device, size)? != *sha256 {
        return Err(WriteError::Mismatch);
    }
    Ok(eviction)
}

/// A root of unknown bytes must not run as this system: without its superblock
/// the kernel stops at the mount, and only a reflash goes on from there.
fn disable_root(device: &File) -> io::Result<()> {
    device.write_all_at(&[0; ROOT_HEADER], 0)?;
    device.sync_data()
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
    /// A partition write started and did not complete. The root is left unable
    /// to mount and the device needs a reflash, unless only the ticket failed.
    Failed,
}

/// One step before the first partition write.
type Step<S> = fn(&mut S) -> io::Result<()>;

/// Runs the raw write. Every step that can still be undone by a reboot comes
/// before the first partition write: stopping the system, the read-only root,
/// releasing the old boot partition, and finding out that both partitions open
/// and take their images. ROOTFS is written before BOOT, and the ticket is
/// published last. The old boot partition still holds this transaction's ticket,
/// which would bind to the new root on the old kernel, so a failure on either
/// partition leaves a root that cannot mount. The caller reboots after any
/// outcome.
pub fn run_writer<S: WriterSystem>(system: &mut S, plan: &WritePlan<'_>) -> Outcome {
    let steps: [(&str, Step<S>); 3] = [
        ("stop services", S::stop_others),
        ("read-only root", S::freeze_root),
        ("release boot", S::release_boot),
    ];
    // One at a time: a failed step must not let the next one run.
    for (step, run) in steps {
        system.log(&format!("raw write step: {step}"));
        if let Err(error) = run(system) {
            system.log(&format!("raw write not started: {step} failed: {error}"));
            return Outcome::NotStarted;
        }
    }
    // The images were verified before they went through a spool on the data
    // partition. This is the last moment a bad read costs nothing.
    for (index, partition) in [(0, Partition::Boot), (1, Partition::Rootfs)] {
        match hash_of(plan.images[index], plan.sizes[index]) {
            Ok(hash) if hash == plan.sha256[index] => {}
            Ok(_) => {
                system.log(&format!(
                    "raw write not started: the {partition:?} image changed"
                ));
                return Outcome::NotStarted;
            }
            Err(error) => {
                system.log(&format!(
                    "raw write not started: the {partition:?} image: {error}"
                ));
                return Outcome::NotStarted;
            }
        }
    }
    let (rootfs, boot) = match open_partitions(system, plan) {
        Ok(devices) => devices,
        Err(error) => {
            system.log(&format!("raw write not started: {error}"));
            return Outcome::NotStarted;
        }
    };
    system.log("raw write: writing and verifying Rootfs");
    let written =
        write_root(plan.images[1], &rootfs, plan.sizes[1], &plan.sha256[1]).and_then(|eviction| {
            system.log(&format!(
                "raw write: Rootfs written and verified after {eviction}, writing and verifying Boot"
            ));
            write_image(plan.images[0], &boot, plan.sizes[0], &plan.sha256[0])
        });
    let eviction = match written {
        Ok(eviction) => eviction,
        Err(error) => {
            system.log(&format!("raw write failed: {error}"));
            if let Err(error) = disable_root(&rootfs) {
                system.log(&format!("raw write: ROOTFS not disabled: {error}"));
            }
            return Outcome::Failed;
        }
    };
    system.log(&format!(
        "raw write: Boot written and verified after {eviction}"
    ));
    drop((rootfs, boot));
    system.log("raw write: publishing restore ticket");
    if let Err(error) = system.publish_ticket(plan.ticket) {
        system.log(&format!(
            "raw write failed: restore ticket not published: {error}"
        ));
        return Outcome::Failed;
    }
    system.log("raw write complete");
    Outcome::Written
}

fn open_partitions<S: WriterSystem>(system: &mut S, plan: &WritePlan<'_>) -> Result<(File, File)> {
    let mut open = |partition, size| -> Result<File> {
        system.log(&format!("raw write: opening {partition:?}"));
        let device = system.open_partition(partition)?;
        fits(&device, size)?;
        Ok(device)
    };
    Ok((
        open(Partition::Rootfs, plan.sizes[1])?,
        open(Partition::Boot, plan.sizes[0])?,
    ))
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

    /// The transfer context these arguments bind. The broker sends the images
    /// under it; the writer receives them only under the same one.
    pub fn context(&self) -> &TransferContext {
        &self.context
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
            system.log(&format!(
                "raw writer received verified inputs: version={}",
                arguments.version
            ));
            quiet_output();
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

/// stdout and stderr may be a log file on the root filesystem that is about
/// to be overwritten: the broker's own is `/run/nanokvm-native.log`.
fn quiet_output() {
    if let Ok(null) = OpenOptions::new().write(true).open("/dev/null") {
        for fd in [1, 2] {
            let _ = nix::unistd::dup2(null.as_raw_fd(), fd);
        }
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
