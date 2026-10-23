use super::*;
use std::io::Write;
use tempfile::tempfile;

fn image(bytes: &[u8]) -> File {
    let mut file = tempfile().unwrap();
    file.write_all(bytes).unwrap();
    file
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn contents(file: &File, size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    file.read_exact_at(&mut bytes, 0).unwrap();
    bytes
}

#[test]
fn the_image_is_written_from_the_start_and_reads_back_whole() {
    // Larger than one chunk and not a multiple of it.
    let bytes: Vec<u8> = (0..CHUNK * 2 + 4097).map(|i| (i * 7 % 251) as u8).collect();
    let device = image(&vec![0xee; bytes.len() + 8192]);
    write_image(&image(&bytes), &device, bytes.len() as u64, &digest(&bytes)).unwrap();
    assert_eq!(contents(&device, bytes.len()), bytes);
    // The rest of the partition is left as it was.
    let mut tail = vec![0; 8192];
    device.read_exact_at(&mut tail, bytes.len() as u64).unwrap();
    assert!(tail.iter().all(|byte| *byte == 0xee));
}

#[test]
fn a_partition_smaller_than_the_image_is_never_written() {
    let bytes = vec![7; 4096];
    let device = image(&vec![0xee; 4095]);
    assert!(matches!(
        write_image(&image(&bytes), &device, 4096, &digest(&bytes)),
        Err(WriteError::TooSmall)
    ));
    assert_eq!(contents(&device, 4095), vec![0xee; 4095]);
}

#[test]
fn a_read_back_that_differs_from_the_authenticated_digest_fails() {
    let bytes = vec![7; 4096];
    let device = image(&vec![0; 4096]);
    let mut other = digest(&bytes);
    other[0] ^= 1;
    assert!(matches!(
        write_image(&image(&bytes), &device, 4096, &other),
        Err(WriteError::Mismatch)
    ));
    // A short source is an I/O error, not a partial success.
    let device = image(&vec![0; 8192]);
    assert!(matches!(
        write_image(&image(&bytes), &device, 8192, &digest(&[7; 8192])),
        Err(WriteError::Io(_))
    ));
}

#[test]
fn an_empty_image_reads_back_as_the_empty_digest() {
    let device = image(b"unchanged");
    write_image(&image(b""), &device, 0, &digest(b"")).unwrap();
    assert_eq!(contents(&device, 9), b"unchanged");
}

#[test]
fn the_read_back_comes_from_the_partition_not_from_the_image() {
    let bytes = vec![7; 8192];
    let device = image(&vec![0; 8192]);
    let alias = device.try_clone().unwrap();
    AFTER_SYNC.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || alias.write_all_at(&[8], 4096).unwrap()))
    });
    let result = write_image(&image(&bytes), &device, 8192, &digest(&bytes));
    AFTER_SYNC.with(|hook| *hook.borrow_mut() = None);
    assert!(matches!(result, Err(WriteError::Mismatch)));
}
