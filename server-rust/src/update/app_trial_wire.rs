//! Data framing shared by the backend, independent owner and controller.
//! A valid frame alone supplies no installation or process authority.
use std::io;

pub const BYTES: usize = 32;
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Begin = 1,
    Ready = 2,
    Commit = 3,
}
pub fn frame(event: Event, transaction: [u8; 16]) -> io::Result<[u8; BYTES]> {
    if transaction == [0; 16] {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut bytes = [0; BYTES];
    bytes[..8].copy_from_slice(b"NKAPPT01");
    bytes[8] = event as u8;
    bytes[16..].copy_from_slice(&transaction);
    Ok(bytes)
}
pub fn parse(bytes: &[u8; BYTES], event: Event) -> io::Result<[u8; 16]> {
    if &bytes[..8] != b"NKAPPT01"
        || bytes[8] != event as u8
        || bytes[9..16] != [0; 7]
        || bytes[16..] == [0; 16]
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    bytes[16..]
        .try_into()
        .map_err(|_| io::ErrorKind::InvalidData.into())
}
