//! Read raw update inputs directly from an authenticated public snapshot.
//! No extracted pathname, stage JSON, tar ownership or device name supplied by
//! a USB host becomes authorization. The legacy writer is NOT yet a consumer
//! of these image descriptors; its replacement is a separate required gate.

use super::{
    AppError, MAX_SYSTEM_UPDATE_PAYLOAD_BYTES, PublicSnapshot, Result, StageDirectory,
    SystemLatest, SystemManifest, SystemManifestRawImage, raw_image_payload_stored_size,
    validate_manifest_shape, validate_raw_image_manifest,
};
use flate2::bufread::GzDecoder;
use sha2::{Digest, Sha256};
use std::io::{self, BufRead, BufReader, Read, Seek};

const BLOCK: usize = 512;
const MAX_MANIFEST: u64 = 128 * 1024;
const MAX_ZERO_TRAILER: usize = 64 * 1024;

pub(super) struct BundlePreflight {
    pub manifest: SystemManifest,
    // Canonical order: BOOT, ROOTFS. Only fully checked, expanded O_RDONLY
    // anonymous images survive. Never an executable/runtime provenance proof.
    pub raw_images: Option<[PublicSnapshot; 2]>,
}

pub(super) fn capture(
    source: &mut PublicSnapshot,
    directory: &StageDirectory,
    latest: &SystemLatest,
) -> Result<BundlePreflight> {
    source.rewind()?;
    let mut archive = GzDecoder::new(BufReader::with_capacity(64 * 1024, source));
    let first = read_header(&mut archive)?.ok_or_else(invalid)?;
    if first.name != "manifest.json"
        || first.directory
        || first.size == 0
        || first.size > MAX_MANIFEST
    {
        return Err(invalid());
    }
    let mut bytes = vec![0; first.size as usize];
    archive.read_exact(&mut bytes)?;
    read_padding(&mut archive, first.size)?;
    let manifest: SystemManifest = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::BadRequest("invalid system bundle manifest".into()))?;
    validate_manifest_shape(&manifest, latest)?;
    if manifest.raw_images.is_empty() {
        // File updates retain their existing payload validator. Do not claim
        // this early return verifies their remaining tar/gzip framing.
        return Ok(BundlePreflight {
            manifest,
            raw_images: None,
        });
    }
    validate_raw_set(&manifest)?;
    let images = capture_raw_images(&mut archive, directory, &manifest)?;
    // GzDecoder is single-member, validates CRC/ISIZE only when drained, and
    // preserves unread compressed data in its BufReader. Reject a second gzip
    // member or any compressed suffix instead of silently accepting it.
    require_compressed_eof(archive.into_inner())?;
    Ok(BundlePreflight {
        manifest,
        raw_images: Some(images),
    })
}

fn validate_raw_set(manifest: &SystemManifest) -> Result<()> {
    if !manifest.files.is_empty() || manifest.raw_images.len() != 2 {
        return Err(invalid());
    }
    let mut raw_size = 0_u64;
    let mut stored_size = 0_u64;
    let mut boot = false;
    let mut rootfs = false;
    for image in &manifest.raw_images {
        validate_raw_image_manifest(image)?;
        let seen = match image.label.as_str() {
            "BOOT" => &mut boot,
            "ROOTFS" => &mut rootfs,
            _ => return Err(invalid()),
        };
        if std::mem::replace(seen, true) {
            return Err(invalid());
        }
        raw_size = raw_size.checked_add(image.size).ok_or_else(invalid)?;
        stored_size = stored_size
            .checked_add(raw_image_payload_stored_size(image)?)
            .ok_or_else(invalid)?;
    }
    if !boot
        || !rootfs
        || raw_size > MAX_SYSTEM_UPDATE_PAYLOAD_BYTES
        || stored_size > MAX_SYSTEM_UPDATE_PAYLOAD_BYTES
    {
        return Err(invalid());
    }
    Ok(())
}

fn capture_raw_images(
    archive: &mut impl Read,
    directory: &StageDirectory,
    manifest: &SystemManifest,
) -> Result<[PublicSnapshot; 2]> {
    let mut images: [Option<PublicSnapshot>; 2] = [None, None];
    let mut directories = [false; 2];
    // Exactly two directories and two images, in either producer image order.
    for _ in 0..4 {
        let entry = read_header(archive)?.ok_or_else(invalid)?;
        if entry.directory {
            let index = match entry.name.as_str() {
                "payload/" => 0,
                "payload/images/" => 1,
                _ => return Err(invalid()),
            };
            if entry.size != 0 || std::mem::replace(&mut directories[index], true) {
                return Err(invalid());
            }
            continue;
        }
        let image = manifest
            .raw_images
            .iter()
            .find(|image| entry.name == format!("payload/{}", image.payload))
            .ok_or_else(invalid)?;
        let index = usize::from(image.label == "ROOTFS");
        if images[index].is_some() || entry.size != raw_image_payload_stored_size(image)? {
            return Err(invalid());
        }
        images[index] = Some(capture_image(archive, directory, image)?);
        read_padding(archive, entry.size)?;
    }
    if directories != [true, true] || read_header(archive)?.is_some() {
        return Err(invalid());
    }
    read_zero_trailer(archive)?;
    let [boot, rootfs] = images;
    Ok([boot.ok_or_else(invalid)?, rootfs.ok_or_else(invalid)?])
}

fn capture_image(
    archive: &mut impl Read,
    directory: &StageDirectory,
    image: &SystemManifestRawImage,
) -> Result<PublicSnapshot> {
    let expected = decode_sha256(&image.sha256)?;
    let mut member = archive.take(raw_image_payload_stored_size(image)?);
    let result = if image.compression.as_deref() == Some("gzip") {
        let mut stored = HashedReader {
            source: &mut member,
            hash: Sha256::new(),
        };
        let mut gzip = GzDecoder::new(BufReader::with_capacity(64 * 1024, &mut stored));
        let snapshot = PublicSnapshot::capture_sha256(directory, &mut gzip, image.size, &expected)
            .map_err(|error| AppError::BadRequest(error.to_string()))?;
        require_compressed_eof(gzip.into_inner())?;
        let actual: [u8; 32] = stored.hash.finalize().into();
        let compressed = decode_sha256(image.compressed_sha256.as_deref().ok_or_else(invalid)?)?;
        if actual != compressed {
            return Err(invalid());
        }
        snapshot
    } else {
        PublicSnapshot::capture_sha256(directory, &mut member, image.size, &expected)
            .map_err(|error| AppError::BadRequest(error.to_string()))?
    };
    if member.limit() != 0 {
        return Err(invalid());
    }
    Ok(result)
}

struct HashedReader<R> {
    source: R,
    hash: Sha256,
}

impl<R: Read> Read for HashedReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = self.source.read(out)?;
        self.hash.update(&out[..count]);
        Ok(count)
    }
}

fn require_compressed_eof(mut source: impl BufRead) -> Result<()> {
    if !source.fill_buf()?.is_empty() {
        return Err(invalid());
    }
    Ok(())
}

struct Entry {
    name: String,
    size: u64,
    directory: bool,
}

fn read_header(source: &mut impl Read) -> Result<Option<Entry>> {
    let mut block = [0_u8; BLOCK];
    source.read_exact(&mut block)?;
    if block.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    // Inspect raw headers before any extension body is read. tar::Archive's
    // normal iterator consumes GNU/PAX extension bodies and can allocate them.
    let directory = match block[156] {
        0 | b'0' => false,
        b'5' => true,
        _ => return Err(invalid()),
    };
    // The producer uses ordinary octal, never GNU base-256 encodings. Bound
    // accepted framing explicitly rather than inheriting every tar extension.
    for field in [&block[100..108], &block[124..136], &block[148..156]] {
        if field
            .iter()
            .any(|byte| !matches!(*byte, 0 | b' ' | b'0'..=b'7'))
        {
            return Err(invalid());
        }
    }
    let header = tar::Header::from_byte_slice(&block);
    let checksum: u32 = block[..148]
        .iter()
        .chain(&block[156..])
        .map(|byte| u32::from(*byte))
        .sum::<u32>()
        + 8 * u32::from(b' ');
    if header.cksum()? != checksum
        || header.mode()? & !0o777 != 0
        || block[157..257].iter().any(|byte| *byte != 0)
    {
        return Err(invalid());
    }
    if &block[257..263] == b"ustar\0" && &block[263..265] == b"00" {
        if block[345..].iter().any(|byte| *byte != 0) {
            return Err(invalid());
        }
    } else if &block[257..265] == b"ustar  \0" {
        // GNU atime/ctime are ignored metadata, not authority. No offset,
        // long-name or sparse representation is accepted, even on regulars.
        if block[369..].iter().any(|byte| *byte != 0) {
            return Err(invalid());
        }
    } else {
        return Err(invalid());
    }
    let end = block[..100]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(100);
    if block[end..100].iter().any(|byte| *byte != 0) {
        return Err(invalid());
    }
    let name = std::str::from_utf8(&block[..end]).map_err(|_| invalid())?;
    let size = header.entry_size()?;
    if size > MAX_SYSTEM_UPDATE_PAYLOAD_BYTES {
        return Err(invalid());
    }
    Ok(Some(Entry {
        name: name.to_owned(),
        size,
        directory,
    }))
}

fn read_padding(source: &mut impl Read, size: u64) -> Result<()> {
    let padding = (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64;
    let mut bytes = [0; BLOCK];
    source.read_exact(&mut bytes[..padding as usize])?;
    if bytes[..padding as usize].iter().any(|byte| *byte != 0) {
        return Err(invalid());
    }
    Ok(())
}

// One zero header has already been consumed. Require at least a second one,
// then only complete zero blocks up to a bounded conventional record padding.
fn read_zero_trailer(source: &mut impl Read) -> Result<()> {
    let mut bytes = [0; BLOCK];
    let mut length = BLOCK;
    while source.read(&mut bytes[..1])? != 0 {
        source.read_exact(&mut bytes[1..])?;
        length += BLOCK;
        if length > MAX_ZERO_TRAILER || bytes.iter().any(|byte| *byte != 0) {
            return Err(invalid());
        }
    }
    if length < 2 * BLOCK {
        return Err(invalid());
    }
    Ok(())
}

fn decode_sha256(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let mut result = [0; 32];
    for (byte, hex) in result.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        let hex = std::str::from_utf8(hex).map_err(|_| invalid())?;
        *byte = u8::from_str_radix(hex, 16).map_err(|_| invalid())?;
    }
    Ok(result)
}

fn invalid() -> AppError {
    AppError::BadRequest("invalid raw system bundle framing or payload".into())
}

#[cfg(test)]
#[path = "system_update_bundle_tests.rs"]
mod tests;
