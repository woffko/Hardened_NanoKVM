use std::{
    collections::{BTreeMap, btree_map::Entry},
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::OpenOptionsExt,
    },
    path::{Path, PathBuf},
};

use flate2::read::GzDecoder;
use tar::{Archive, EntryType};

use super::app_space::Footprint;
use crate::{AppError, Result, system::files::clean_relative_path};

const MAX_SYNCED_ARCHIVE_FILE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy)]
struct AppLimits {
    bytes: u64,
    members: usize,
    path: usize,
}

const APP_LIMITS: AppLimits = AppLimits {
    bytes: 256 * 1024 * 1024,
    members: 8192,
    path: 4096,
};

/// The caller owns a fresh private rootfs destination and an immutable archive
/// descriptor. GNU/ustar directories and regular files are the package format;
/// raw iteration bounds GNU long names before tar can allocate their bodies.
pub(crate) fn extract_app_tar_gz(src: impl Read, dest: &Path) -> Result<PathBuf> {
    extract_app_tar_gz_limited(src, dest, APP_LIMITS)
}

/// The same parser and footer/type/path/member limits as extraction, but no
/// output writes. The caller must rewind the same immutable archive afterwards.
pub(super) fn inspect_app_tar_gz(src: impl Read, unit: u64) -> Result<Footprint> {
    Ok(read_app_tar_gz(src, None, APP_LIMITS, unit)?.1)
}

fn extract_app_tar_gz_limited(src: impl Read, dest: &Path, limits: AppLimits) -> Result<PathBuf> {
    Ok(read_app_tar_gz(src, Some(dest), limits, 4096)?.0)
}

fn read_app_tar_gz(
    src: impl Read,
    dest: Option<&Path>,
    limits: AppLimits,
    unit: u64,
) -> Result<(PathBuf, Footprint)> {
    let mut footprint = Footprint::new(unit)?;
    if let Some(dest) = dest {
        fs::create_dir(dest)?;
    }
    let gz = flate2::bufread::GzDecoder::new(BufReader::new(src));
    let mut archive = Archive::new(BoundedTar {
        reader: gz,
        remaining: limits.bytes,
    });
    let mut first_top_level = None;
    let mut long_name = None;
    let mut members = 0;
    let mut payload = 0_u64;
    // One bounded map, not separate duplicated path inventories. true marks a
    // regular file; implicit parents and explicit directories are false.
    let mut output_paths = BTreeMap::new();
    for entry in archive.entries()?.raw(true) {
        let mut entry = entry?;
        members += 1;
        if members > limits.members {
            return Err(AppError::BadRequest("too many app archive members".into()));
        }
        let kind = entry.header().entry_type();
        let size = entry.size();
        if kind.is_gnu_longname() {
            if long_name.is_some() || size == 0 || size > limits.path as u64 + 1 {
                return Err(AppError::BadRequest("invalid app archive long name".into()));
            }
            let mut bytes = Vec::with_capacity(size as usize);
            entry.read_to_end(&mut bytes)?;
            if bytes.len() as u64 != size {
                return Err(AppError::BadRequest(
                    "truncated app archive long name".into(),
                ));
            }
            if bytes.last() == Some(&0) {
                bytes.pop();
            }
            if bytes.is_empty() || bytes.contains(&0) {
                return Err(AppError::BadRequest("invalid app archive long name".into()));
            }
            long_name = Some(PathBuf::from(OsString::from_vec(bytes)));
            continue;
        }
        if kind != EntryType::Directory && kind != EntryType::Regular {
            return Err(AppError::BadRequest(
                "unsupported app archive entry type".into(),
            ));
        }
        let path = match long_name.take() {
            Some(path) => path,
            None => entry.path()?.into_owned(),
        };
        if path.as_os_str().as_bytes().len() > limits.path || path.components().count() > 64 {
            return Err(AppError::BadRequest("app archive path is too long".into()));
        }
        let relative = clean_relative_path(&path)?;
        let mut prefix = PathBuf::new();
        for component in relative.components() {
            prefix.push(component.as_os_str());
            let regular = prefix == relative && kind == EntryType::Regular;
            match output_paths.entry(prefix.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(regular);
                    footprint.path(regular)?;
                }
                Entry::Occupied(entry) if *entry.get() || regular => {
                    return Err(AppError::BadRequest("conflicting app archive paths".into()));
                }
                Entry::Occupied(_) => {}
            }
            if output_paths.len() > limits.members {
                return Err(AppError::BadRequest(
                    "too many implicit app archive paths".into(),
                ));
            }
        }
        let first = relative
            .components()
            .next()
            .ok_or_else(|| AppError::BadRequest("empty app archive path".into()))?;
        let top_level = dest.unwrap_or(Path::new("")).join(first.as_os_str());
        // The published GNU packages include this top-level inventory beside
        // kvmapp. It is ordinary data, never an authorization receipt.
        if relative != Path::new("MANIFEST.txt") || kind != EntryType::Regular {
            match &first_top_level {
                None => first_top_level = Some(top_level),
                Some(expected) if expected == &top_level => {}
                Some(_) => return Err(AppError::BadRequest("multiple app archive roots".into())),
            }
        }
        if kind == EntryType::Directory {
            if size != 0 {
                return Err(AppError::BadRequest(
                    "app archive directory has data".into(),
                ));
            }
            if let Some(dest) = dest {
                fs::create_dir_all(safe_join(dest, &relative)?)?;
            }
            continue;
        }
        payload = payload
            .checked_add(size)
            .filter(|bytes| *bytes <= limits.bytes)
            .ok_or_else(|| AppError::BadRequest("app archive expands beyond its limit".into()))?;
        footprint.file(size)?;
        let copied = if let Some(dest) = dest {
            let target = safe_join(dest, &relative)?;
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            reject_symlink_parent(dest, &target)?;
            let mut out = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(target)?;
            let copied = io::copy(&mut entry, &mut out)?;
            out.sync_all()?;
            copied
        } else {
            io::copy(&mut entry, &mut io::sink())?
        };
        if copied != size {
            return Err(AppError::BadRequest("truncated app archive member".into()));
        }
    }
    if long_name.is_some() {
        return Err(AppError::BadRequest("orphan app archive long name".into()));
    }
    // Reading only to tar's terminator would skip gzip footer/CRC errors. The
    // remaining decoded tar bytes may only be zero padding, under the same cap.
    let mut decoded = archive.into_inner();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = decoded.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if buffer[..count].iter().any(|byte| *byte != 0) {
            return Err(AppError::BadRequest(
                "app archive has nonzero tar tail".into(),
            ));
        }
    }
    let mut compressed = decoded.reader.into_inner();
    if !compressed.fill_buf()?.is_empty() {
        return Err(AppError::BadRequest(
            "app archive has trailing compressed data".into(),
        ));
    }
    let root = first_top_level.ok_or_else(|| AppError::BadRequest("empty archive".into()))?;
    Ok((root, footprint))
}

struct BoundedTar<R> {
    reader: R,
    remaining: u64,
}

impl<R: Read> Read for BoundedTar<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            return if self.reader.read(&mut [0; 1])? == 0 {
                Ok(0)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "app tar byte budget exceeded",
                ))
            };
        }
        let limit = self.remaining.min(bytes.len() as u64) as usize;
        let count = self.reader.read(&mut bytes[..limit])?;
        self.remaining -= count as u64;
        Ok(count)
    }
}

pub fn safe_join(root: &Path, member_name: &Path) -> Result<PathBuf> {
    let relative = clean_relative_path(member_name)?;
    let joined = root.join(relative);
    if !joined.starts_with(root) {
        return Err(AppError::BadRequest(
            "archive member escapes extraction root".to_string(),
        ));
    }
    Ok(joined)
}

pub fn extract_tar_gz_safe(src: &Path, dest: &Path) -> Result<PathBuf> {
    let file = fs::File::open(src)?;
    extract_tar_gz_reader(file, dest)
}

pub(crate) fn extract_tar_gz_reader(src: impl Read, dest: &Path) -> Result<PathBuf> {
    fs::create_dir_all(dest)?;
    let gz = GzDecoder::new(src);
    let mut archive = Archive::new(gz);
    let mut first_top_level = None;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let target = safe_join(dest, &path)?;

        if first_top_level.is_none()
            && let Some(first) = path.components().next()
        {
            first_top_level = Some(dest.join(first.as_os_str()));
        }

        match entry.header().entry_type() {
            EntryType::Directory => fs::create_dir_all(&target)?,
            EntryType::Regular => {
                let size = entry.header().size()?;
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                reject_symlink_parent(dest, &target)?;
                let mut out = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o644)
                    .open(&target)?;
                io::copy(&mut entry, &mut out)?;
                out.flush()?;
                if size <= MAX_SYNCED_ARCHIVE_FILE_BYTES {
                    out.sync_all()?;
                }
            }
            _ => {
                return Err(AppError::BadRequest(
                    "unsupported archive entry type".to_string(),
                ));
            }
        }
    }

    first_top_level.ok_or_else(|| AppError::BadRequest("empty archive".to_string()))
}

fn reject_symlink_parent(root: &Path, target: &Path) -> Result<()> {
    let mut current = target.parent();
    while let Some(path) = current {
        if path == root {
            return Ok(());
        }
        if fs::symlink_metadata(path)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(AppError::BadRequest(
                "archive target crosses symlink parent".to_string(),
            ));
        }
        current = path.parent();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn tar(entries: &[(&str, EntryType, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, kind, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o755);
            header.set_entry_type(*kind);
            header.set_cksum();
            builder.append_data(&mut header, name, *bytes).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn app_rejected(bytes: &[u8]) {
        let root = tempfile::tempdir().unwrap();
        assert!(extract_app_tar_gz(bytes, &root.path().join("extract")).is_err());
        assert!(inspect_app_tar_gz(bytes, 4096).is_err());
    }

    #[test]
    fn app_inspection_counts_unique_paths_without_creating_any_output() {
        let bytes = gzip(&tar(&[
            ("MANIFEST.txt", EntryType::Regular, b"inventory"),
            ("kvmapp", EntryType::Directory, b""),
            ("kvmapp", EntryType::Directory, b""),
            ("kvmapp/sub/empty", EntryType::Regular, b""),
            ("kvmapp/sub/data", EntryType::Regular, b"data"),
        ]));
        let footprint = inspect_app_tar_gz(bytes.as_slice(), 4096).unwrap();
        // extract + five unique paths (three files/two dirs), two data blocks.
        footprint
            .check(super::super::app_space::Capacity::fixture(
                4096,
                super::super::app_space::RECOVERY_BYTES + 10 * 4096,
                128 + 6,
            ))
            .unwrap();
        assert!(
            footprint
                .check(super::super::app_space::Capacity::fixture(
                    4096,
                    super::super::app_space::RECOVERY_BYTES + 10 * 4096 - 1,
                    128 + 6,
                ))
                .is_err()
        );
        let root = tempfile::tempdir().unwrap();
        extract_app_tar_gz(bytes.as_slice(), &root.path().join("extract")).unwrap();
        assert_eq!(
            fs::read(root.path().join("extract/kvmapp/sub/data")).unwrap(),
            b"data"
        );
    }

    #[test]
    fn app_inspection_and_extraction_both_reject_file_directory_collisions() {
        for entries in [
            vec![
                ("kvmapp/parent", EntryType::Regular, b"x".as_slice()),
                ("kvmapp/parent/child", EntryType::Regular, b"y"),
            ],
            vec![
                ("kvmapp/parent/child", EntryType::Regular, b"x".as_slice()),
                ("kvmapp/parent", EntryType::Regular, b"y"),
            ],
            vec![
                ("kvmapp/parent", EntryType::Regular, b"x".as_slice()),
                ("kvmapp/parent", EntryType::Directory, b""),
            ],
        ] {
            app_rejected(&gzip(&tar(&entries)));
        }
    }

    #[test]
    fn app_extracts_gnu_regular_tree_and_bounded_long_names() {
        let root = tempfile::tempdir().unwrap();
        let long = format!("kvmapp/{}/asset", "long".repeat(40));
        let bytes = gzip(&tar(&[
            ("MANIFEST.txt", EntryType::Regular, b"not a trust receipt"),
            ("kvmapp", EntryType::Directory, b""),
            ("kvmapp/server", EntryType::Directory, b""),
            (
                "kvmapp/server/NanoKVM-Server",
                EntryType::Regular,
                b"synthetic backend",
            ),
            (&long, EntryType::Regular, b"long path bytes"),
        ]));
        let dest = root.path().join("extract");
        assert_eq!(
            extract_app_tar_gz(bytes.as_slice(), &dest).unwrap(),
            dest.join("kvmapp")
        );
        assert_eq!(fs::read(dest.join(long)).unwrap(), b"long path bytes");
        assert_eq!(
            fs::read(dest.join("kvmapp/server/NanoKVM-Server")).unwrap(),
            b"synthetic backend"
        );
        assert!(extract_app_tar_gz(bytes.as_slice(), &dest).is_err());
    }

    #[test]
    fn app_rejects_links_special_types_duplicate_files_and_multiple_roots() {
        for kind in [
            EntryType::Symlink,
            EntryType::Link,
            EntryType::Fifo,
            EntryType::Char,
            EntryType::Block,
            EntryType::GNUSparse,
            EntryType::XHeader,
            EntryType::XGlobalHeader,
            EntryType::GNULongLink,
        ] {
            app_rejected(&gzip(&tar(&[("kvmapp/foreign", kind, b"")])));
        }
        app_rejected(&gzip(&tar(&[
            ("kvmapp/file", EntryType::Regular, b"first"),
            ("kvmapp/file", EntryType::Regular, b"second"),
        ])));
        app_rejected(&gzip(&tar(&[
            ("kvmapp/file", EntryType::Regular, b"first"),
            ("other/file", EntryType::Regular, b"second"),
        ])));
        app_rejected(&gzip(&tar(&[(
            "kvmapp",
            EntryType::Directory,
            b"directory payload",
        )])));
    }

    #[test]
    fn app_enforces_member_path_payload_and_decoded_padding_budgets() {
        let bytes = gzip(&tar(&[
            ("kvmapp/a", EntryType::Regular, b"a"),
            ("kvmapp/b", EntryType::Regular, b"b"),
        ]));
        for limits in [
            AppLimits {
                bytes: 4096,
                members: 1,
                path: 4096,
            },
            AppLimits {
                bytes: 4096,
                members: 10,
                path: 4,
            },
            AppLimits {
                bytes: 1024,
                members: 10,
                path: 4096,
            },
        ] {
            let root = tempfile::tempdir().unwrap();
            assert!(
                extract_app_tar_gz_limited(bytes.as_slice(), &root.path().join("extract"), limits)
                    .is_err()
            );
        }
        let implicit = gzip(&tar(&[("kvmapp/a/b/c/d/file", EntryType::Regular, b"")]));
        let root = tempfile::tempdir().unwrap();
        assert!(
            extract_app_tar_gz_limited(
                implicit.as_slice(),
                &root.path().join("extract"),
                AppLimits {
                    bytes: 4096,
                    members: 4,
                    path: 4096
                }
            )
            .is_err()
        );
        let mut padded = tar(&[("kvmapp/a", EntryType::Regular, b"a")]);
        padded.extend_from_slice(&[0; 8192]);
        let bytes = gzip(&padded);
        let root = tempfile::tempdir().unwrap();
        assert!(
            extract_app_tar_gz_limited(
                bytes.as_slice(),
                &root.path().join("extract"),
                AppLimits {
                    bytes: 4096,
                    members: 10,
                    path: 4096
                }
            )
            .is_err()
        );
        let payload = [42; 8192];
        let bytes = gzip(&tar(&[("kvmapp/a", EntryType::Regular, &payload)]));
        let root = tempfile::tempdir().unwrap();
        assert!(
            extract_app_tar_gz_limited(
                bytes.as_slice(),
                &root.path().join("extract"),
                AppLimits {
                    bytes: 4096,
                    members: 10,
                    path: 4096
                }
            )
            .is_err()
        );
    }

    #[test]
    fn app_reads_gzip_footer_and_rejects_crc_truncation_and_both_tail_kinds() {
        let tar = tar(&[("kvmapp/file", EntryType::Regular, b"payload")]);
        let good = gzip(&tar);
        let mut corrupt = good.clone();
        let crc = corrupt.len() - 8;
        corrupt[crc] ^= 1;
        app_rejected(&corrupt);
        app_rejected(&good[..good.len() - 4]);
        let mut trailing = good.clone();
        trailing.extend_from_slice(b"untrusted tail");
        app_rejected(&trailing);
        let mut concatenated = good;
        concatenated.extend_from_slice(&gzip(b"second gzip stream"));
        app_rejected(&concatenated);
        let mut tar_tail = tar;
        tar_tail.extend_from_slice(b"nonzero behind tar terminator");
        app_rejected(&gzip(&tar_tail));
    }

    #[test]
    fn app_rejects_raw_traversal_and_oversized_duplicate_or_orphan_long_names() {
        for name in [
            b"../escape".as_slice(),
            b"/absolute",
            b"kvmapp/../../escape",
        ] {
            let mut header = tar::Header::new_gnu();
            header.as_mut_bytes()[..name.len()].copy_from_slice(name);
            header.set_size(0);
            header.set_entry_type(EntryType::Regular);
            header.set_cksum();
            let mut raw = header.as_bytes().to_vec();
            raw.extend_from_slice(&[0; 1024]);
            app_rejected(&gzip(&raw));
        }
        for entries in [
            vec![
                (
                    "././@LongLink",
                    EntryType::GNULongName,
                    b"../escape\0".as_slice(),
                ),
                ("kvmapp/a", EntryType::Regular, b""),
            ],
            vec![(
                "././@LongLink",
                EntryType::GNULongName,
                b"kvmapp/a\0".as_slice(),
            )],
            vec![
                (
                    "././@LongLink",
                    EntryType::GNULongName,
                    b"kvmapp/a\0".as_slice(),
                ),
                (
                    "././@LongLink",
                    EntryType::GNULongName,
                    b"kvmapp/b\0".as_slice(),
                ),
            ],
        ] {
            app_rejected(&gzip(&tar(&entries)));
        }
        let oversized = vec![b'a'; 4098];
        app_rejected(&gzip(&tar(&[(
            "././@LongLink",
            EntryType::GNULongName,
            &oversized,
        )])));
    }

    #[test]
    fn rejects_path_traversal_members() {
        let root = Path::new("/tmp/root");
        assert!(safe_join(root, Path::new("../etc/passwd")).is_err());
        assert!(safe_join(root, Path::new("/etc/passwd")).is_err());
    }

    #[test]
    fn accepts_normal_relative_members() {
        let root = Path::new("/tmp/root");
        assert_eq!(
            safe_join(root, Path::new("latest/bin/server")).unwrap(),
            Path::new("/tmp/root/latest/bin/server")
        );
    }
}
