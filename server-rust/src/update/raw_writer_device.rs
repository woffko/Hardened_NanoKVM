//! The writer process's device operations. Only the raw writer runs these:
//! they stop the whole system and write the SD card's boot and root
//! partitions. Host tests cover only the pure parts (`killable`,
//! `root_is_readonly`).

use super::{Partition, WriterSystem};
use crate::update::restore_capsule::ticket::{RestoreTicket, Store, TicketError};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    process::{Pid, PidfdFlags, Signal, getpid, pidfd_open, pidfd_send_signal},
};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Write},
    os::{
        fd::OwnedFd,
        unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt},
    },
    path::Path,
    thread,
    time::{Duration, Instant},
};

const BOOT_DEVICE: &str = "/dev/mmcblk0p1";
const ROOTFS_DEVICE: &str = "/dev/mmcblk0p2";
/// On devtmpfs, whose mountpoint dentry stays pinned: no path walk to it reads
/// the overwritten root filesystem.
const NEW_BOOT: &str = "/dev/.nanokvm-raw-boot";
const BOOT_OPTIONS: &str = "uid=0,gid=0,fmask=0177,dmask=0077";
const TERM_GRACE: Duration = Duration::from_secs(5);
const KILL_GRACE: Duration = Duration::from_secs(5);
const STEP: Duration = Duration::from_millis(100);
/// `PF_KTHREAD` in the flags field of /proc/PID/stat.
const KERNEL_THREAD: u64 = 0x0020_0000;

/// The device implementation of `WriterSystem`. Never use stderr, which may
/// be on the rootfs being overwritten. The bounded p3 log is diagnostic only,
/// never update authority; kmsg remains available if p3 logging fails.
pub struct DeviceSystem {
    kmsg: Option<File>,
    diagnostic: Option<DiagnosticLog>,
}

const DIAGNOSTIC_LIMIT: usize = 16 * 1024;
const DIAGNOSTIC_HEADER: &[u8] = b"nanokvm raw writer diagnostic v1\n";

struct DiagnosticLog {
    file: File,
    remaining: usize,
}

impl DiagnosticLog {
    fn open() -> io::Result<Self> {
        // Refuse to put the log on the rootfs if /data is not mounted.
        let data_device = fs::metadata("/data")?.dev();
        if data_device == fs::metadata("/")?.dev() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Self::at(Path::new("/data/.nanokvm-writer-log"), data_device)
    }

    fn at(path: &Path, expected_device: u64) -> io::Result<Self> {
        let directory = crate::update::staged_archive::StageDirectory::prepare(path)?;
        let mut next = directory.create_download()?;
        if next.file_mut().metadata()?.dev() != expected_device {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        next.file_mut().write_all(DIAGNOSTIC_HEADER)?;
        let file = next.writer()?;
        // Atomic replacement never follows an existing symlink or writes
        // through a hard link. Keep the writable descriptor across shutdown.
        next.publish("latest.log")?;
        Ok(Self {
            file,
            remaining: DIAGNOSTIC_LIMIT - DIAGNOSTIC_HEADER.len(),
        })
    }

    fn append(&mut self, line: &str) -> io::Result<()> {
        let count = line
            .len()
            .checked_add(1)
            .ok_or(io::ErrorKind::InvalidInput)?;
        if count > self.remaining {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        self.remaining -= count;
        self.file.write_all(line.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.sync_data()
    }
}

impl DeviceSystem {
    pub fn new() -> Self {
        let mut system = Self {
            kmsg: OpenOptions::new().write(true).open("/dev/kmsg").ok(),
            diagnostic: DiagnosticLog::open().ok(),
        };
        if system.diagnostic.is_none() {
            system.log("persistent diagnostic unavailable; using kmsg only");
        }
        system
    }
}

impl Default for DeviceSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl WriterSystem for DeviceSystem {
    /// TERM, then KILL, to every process that existed at the scan, tracked by
    /// pidfd. Processes init respawns afterwards (a console getty) are left
    /// alone; they do not write the root filesystem.
    fn stop_others(&mut self) -> io::Result<()> {
        let mut remaining: Vec<OwnedFd> = victims(Path::new("/proc"), getpid())?
            .into_iter()
            .filter_map(|pid| pidfd_open(pid, PidfdFlags::empty()).ok())
            .collect();
        for (signal, grace) in [(Signal::TERM, TERM_GRACE), (Signal::KILL, KILL_GRACE)] {
            for process in &remaining {
                let _ = pidfd_send_signal(process, signal);
            }
            let started = Instant::now();
            while !remaining.is_empty() && started.elapsed() < grace {
                remaining.retain(|process| !exited(process));
                if !remaining.is_empty() {
                    thread::sleep(STEP);
                }
            }
        }
        if remaining.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "{} processes did not exit after SIGKILL",
                remaining.len()
            )))
        }
    }

    fn freeze_root(&mut self) -> io::Result<()> {
        // Before anything can make devtmpfs read-only too.
        match DirBuilder::new().mode(0o700).create(NEW_BOOT) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        nix::unistd::sync();
        for _ in 0..3 {
            match mount(
                None::<&str>,
                "/",
                None::<&str>,
                MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                None::<&str>,
            ) {
                Ok(()) => return Ok(()),
                Err(nix::Error::EBUSY) => thread::sleep(Duration::from_secs(1)),
                Err(error) => return Err(error.into()),
            }
        }
        // Emergency read-only remount of every filesystem; the images are only
        // read from now on and the new boot mountpoint already exists.
        self.log("normal read-only remount of / is busy; using sysrq u");
        fs::write("/proc/sysrq-trigger", b"u")?;
        for _ in 0..50 {
            if root_is_readonly(&fs::read_to_string("/proc/mounts")?) {
                return Ok(());
            }
            thread::sleep(STEP);
        }
        Err(io::Error::other(
            "the root filesystem did not become read-only",
        ))
    }

    /// The old boot partition must be fully unmounted: a second mount of the
    /// same device would reuse its stale superblock.
    fn release_boot(&mut self) -> io::Result<()> {
        if !fs::read_to_string("/proc/mounts")?
            .lines()
            .any(|line| line.split_whitespace().nth(1) == Some("/boot"))
        {
            return Ok(());
        }
        umount2("/boot", MntFlags::empty()).map_err(io::Error::from)
    }

    fn open_partition(&mut self, partition: Partition) -> io::Result<File> {
        let path = match partition {
            Partition::Boot => BOOT_DEVICE,
            Partition::Rootfs => ROOTFS_DEVICE,
        };
        let device = OpenOptions::new().read(true).write(true).open(path)?;
        if !device.metadata()?.file_type().is_block_device() {
            return Err(io::Error::other(format!("{path} is not a block device")));
        }
        Ok(device)
    }

    fn publish_ticket(&mut self, ticket: &RestoreTicket) -> Result<(), TicketError> {
        mount(
            Some(BOOT_DEVICE),
            NEW_BOOT,
            Some("vfat"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            Some(BOOT_OPTIONS),
        )
        .map_err(io::Error::from)?;
        let published = Store::open_mounted(NEW_BOOT, BOOT_DEVICE)
            .and_then(|mut store| store.publish_prepared(ticket));
        nix::unistd::sync();
        let unmounted = umount2(NEW_BOOT, MntFlags::empty()).map_err(io::Error::from);
        published?;
        unmounted?;
        Ok(())
    }

    fn log(&mut self, line: &str) {
        if let Some(log) = &mut self.diagnostic
            && log.append(line).is_err()
        {
            // e.g. sysrq-u remounted p3 read-only. Logging must not change the
            // writer outcome; retain the already synced prefix for diagnosis.
            self.diagnostic = None;
            if let Some(kmsg) = &mut self.kmsg {
                let _ = kmsg.write_all(
                    b"<3>nanokvm-raw-writer: persistent diagnostic stopped; using kmsg only\n",
                );
            }
        }
        if let Some(kmsg) = &mut self.kmsg {
            let _ = kmsg.write_all(format!("<3>nanokvm-raw-writer: {line}\n").as_bytes());
        }
    }
}

/// Every process in `proc_root` but PID 1, `own`, kernel threads and zombies.
fn victims(proc_root: &Path, own: Pid) -> io::Result<Vec<Pid>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(proc_root)? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
            .and_then(Pid::from_raw)
        else {
            continue;
        };
        if pid.as_raw_nonzero().get() == 1 || pid == own {
            continue;
        }
        // A process that exits during the scan has no stat any more.
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        if killable(&stat) {
            found.push(pid);
        }
    }
    Ok(found)
}

/// From one /proc/PID/stat line: neither a kernel thread nor already exited.
/// The command name may contain spaces and parentheses, so fields are counted
/// after its last `)`.
fn killable(stat: &str) -> bool {
    let Some((_, rest)) = stat.rsplit_once(')') else {
        return false;
    };
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let (Some(state), Some(flags)) = (fields.first(), fields.get(6)) else {
        return false;
    };
    let Ok(flags) = flags.parse::<u64>() else {
        return false;
    };
    !matches!(*state, "Z" | "X" | "x") && flags & KERNEL_THREAD == 0
}

/// Whether the last mount of `/` in a /proc/mounts text is read-only.
fn root_is_readonly(mounts: &str) -> bool {
    mounts
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .rfind(|fields| fields.len() >= 4 && fields[1] == "/")
        .is_some_and(|fields| fields[3].split(',').any(|option| option == "ro"))
}

fn exited(process: &OwnedFd) -> bool {
    let mut fds = [PollFd::new(process, PollFlags::IN)];
    let now = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    matches!(poll(&mut fds, Some(&now)), Ok(1))
}

#[cfg(test)]
#[path = "raw_writer_device_tests.rs"]
mod tests;
