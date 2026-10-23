//! Bounded framing of the signed image's account tables, sent by the sandbox
//! helper that mounted the image to its parent. Shape checks only: the parent
//! must already have authenticated the image it handed over.

use super::restore_native::{self, AccountFiles, MAX_TABLE_BYTES};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"NKACCT01";
const HEADER: usize = MAGIC.len() + 4 * 4;
const ABSENT: u32 = u32::MAX;
/// The largest frame `decode` accepts.
pub const MAX_ENCODED: usize = HEADER + 4 * MAX_TABLE_BYTES;

#[derive(Debug, thiserror::Error)]
#[error("signed image account tables are malformed")]
pub struct AccountWireError;

/// Owned copies of the image's passwd, group, shadow and optional gshadow.
// No Debug/Clone/serde: shadow contents stay in zeroizing buffers.
pub struct SignedAccounts {
    passwd: Zeroizing<Vec<u8>>,
    group: Zeroizing<Vec<u8>>,
    shadow: Zeroizing<Vec<u8>>,
    gshadow: Option<Zeroizing<Vec<u8>>>,
}

impl SignedAccounts {
    pub fn as_files(&self) -> AccountFiles<'_> {
        AccountFiles {
            passwd: &self.passwd,
            group: &self.group,
            shadow: &self.shadow,
            gshadow: self.gshadow.as_deref().map(|bytes| bytes.as_slice()),
        }
    }
}

/// Magic, four little-endian lengths (gshadow `u32::MAX` when absent), then
/// the tables in that order.
pub fn encode(files: &AccountFiles<'_>) -> Result<Zeroizing<Vec<u8>>, AccountWireError> {
    restore_native::validate(files).map_err(|_| AccountWireError)?;
    let tables = [
        Some(files.passwd),
        Some(files.group),
        Some(files.shadow),
        files.gshadow,
    ];
    let mut out = Zeroizing::new(Vec::with_capacity(
        HEADER
            + tables
                .iter()
                .flatten()
                .map(|table| table.len())
                .sum::<usize>(),
    ));
    out.extend_from_slice(MAGIC);
    for table in tables {
        let length = match table {
            Some(table) if table.len() <= MAX_TABLE_BYTES => table.len() as u32,
            Some(_) => return Err(AccountWireError),
            None => ABSENT,
        };
        out.extend_from_slice(&length.to_le_bytes());
    }
    for table in tables.into_iter().flatten() {
        out.extend_from_slice(table);
    }
    Ok(out)
}

pub fn decode(bytes: &[u8]) -> Result<SignedAccounts, AccountWireError> {
    if bytes.len() < HEADER || bytes.len() > MAX_ENCODED || &bytes[..MAGIC.len()] != MAGIC {
        return Err(AccountWireError);
    }
    let mut lengths = [None; 4];
    let mut total = HEADER;
    let (fields, _) = bytes[MAGIC.len()..HEADER].as_chunks::<4>();
    for (index, field) in fields.iter().enumerate() {
        let length = u32::from_le_bytes(*field);
        if length == ABSENT && index == 3 {
            continue;
        }
        let length = length as usize;
        if length > MAX_TABLE_BYTES {
            return Err(AccountWireError);
        }
        lengths[index] = Some(length);
        total += length;
    }
    if total != bytes.len() {
        return Err(AccountWireError);
    }
    let mut offset = HEADER;
    let mut table = |length: Option<usize>| {
        length.map(|length| {
            let table = Zeroizing::new(bytes[offset..offset + length].to_vec());
            offset += length;
            table
        })
    };
    let accounts = SignedAccounts {
        passwd: table(lengths[0]).ok_or(AccountWireError)?,
        group: table(lengths[1]).ok_or(AccountWireError)?,
        shadow: table(lengths[2]).ok_or(AccountWireError)?,
        gshadow: table(lengths[3]),
    };
    restore_native::validate(&accounts.as_files()).map_err(|_| AccountWireError)?;
    Ok(accounts)
}

#[cfg(test)]
#[path = "restore_accounts_tests.rs"]
mod tests;
