//! Bounded framing of the signed image's account tables, sent by the sandbox
//! helper that mounted the image to its parent. Shape checks only: the parent
//! must already have authenticated the image it handed over.

use super::restore_native::{self, AccountFiles, MAX_TABLE_BYTES};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"NKACCT02";
const HEADER: usize = MAGIC.len() + 4 * 4 + 1 + 1;
const ABSENT: u32 = u32::MAX;
/// The longest application version an image may declare.
pub const MAX_APP_VERSION: usize = 32;
/// The largest frame `decode` accepts.
pub const MAX_ENCODED: usize = HEADER + MAX_APP_VERSION + 4 * MAX_TABLE_BYTES;

#[derive(Debug, thiserror::Error)]
#[error("signed image account tables are malformed")]
pub struct AccountWireError;

/// What the image says about itself besides its accounts, read by the same
/// sandbox from the same authenticated mount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageFacts {
    /// The content of `kvmapp/version`, the value early boot will observe.
    pub app_version: String,
    /// The image carries the restore marker, the early helper and its script.
    pub restorable: bool,
}

/// Owned copies of the image's passwd, group, shadow and optional gshadow.
// No Debug/Clone/serde: shadow contents stay in zeroizing buffers.
pub struct SignedAccounts {
    passwd: Zeroizing<Vec<u8>>,
    group: Zeroizing<Vec<u8>>,
    shadow: Zeroizing<Vec<u8>>,
    gshadow: Option<Zeroizing<Vec<u8>>>,
    facts: ImageFacts,
}

impl SignedAccounts {
    pub fn facts(&self) -> &ImageFacts {
        &self.facts
    }

    pub fn as_files(&self) -> AccountFiles<'_> {
        AccountFiles {
            passwd: &self.passwd,
            group: &self.group,
            shadow: &self.shadow,
            gshadow: self.gshadow.as_deref().map(|bytes| bytes.as_slice()),
        }
    }
}

/// Magic, four little-endian lengths (gshadow `u32::MAX` when absent), one
/// restorable byte, the version length, then the tables and the version.
pub fn encode(
    files: &AccountFiles<'_>,
    facts: &ImageFacts,
) -> Result<Zeroizing<Vec<u8>>, AccountWireError> {
    restore_native::validate(files).map_err(|_| AccountWireError)?;
    let version = facts.app_version.as_bytes();
    if version.is_empty() || version.len() > MAX_APP_VERSION {
        return Err(AccountWireError);
    }
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
                .sum::<usize>()
            + version.len(),
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
    out.push(u8::from(facts.restorable));
    out.push(version.len() as u8);
    for table in tables.into_iter().flatten() {
        out.extend_from_slice(table);
    }
    out.extend_from_slice(version);
    Ok(out)
}

pub fn decode(bytes: &[u8]) -> Result<SignedAccounts, AccountWireError> {
    if bytes.len() < HEADER || bytes.len() > MAX_ENCODED || &bytes[..MAGIC.len()] != MAGIC {
        return Err(AccountWireError);
    }
    let mut lengths = [None; 4];
    let (fields, _) = bytes[MAGIC.len()..HEADER - 2].as_chunks::<4>();
    let restorable = match bytes[HEADER - 2] {
        0 => false,
        1 => true,
        _ => return Err(AccountWireError),
    };
    let version_length = bytes[HEADER - 1] as usize;
    if version_length == 0 || version_length > MAX_APP_VERSION {
        return Err(AccountWireError);
    }
    let mut total = HEADER + version_length;
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
    let passwd = table(lengths[0]).ok_or(AccountWireError)?;
    let group = table(lengths[1]).ok_or(AccountWireError)?;
    let shadow = table(lengths[2]).ok_or(AccountWireError)?;
    let gshadow = table(lengths[3]);
    let app_version = std::str::from_utf8(&bytes[offset..])
        .map_err(|_| AccountWireError)?
        .to_string();
    let accounts = SignedAccounts {
        passwd,
        group,
        shadow,
        gshadow,
        facts: ImageFacts {
            app_version,
            restorable,
        },
    };
    restore_native::validate(&accounts.as_files()).map_err(|_| AccountWireError)?;
    Ok(accounts)
}

#[cfg(test)]
#[path = "restore_accounts_tests.rs"]
mod tests;
