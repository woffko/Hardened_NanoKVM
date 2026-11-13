//! Build/runtime shared script framing. Consistency, not provenance or authority.

use sha2::{Digest, Sha256};

pub const HEADER: usize = 48;
pub const MAX_SCRIPT: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    AppRecovery,
    Ethernet,
    Wifi,
    NanoKvm,
}

pub const ROLES: [Role; 4] = [Role::AppRecovery, Role::Ethernet, Role::Wifi, Role::NanoKvm];

impl Role {
    pub fn filename(self) -> &'static str {
        match self {
            Self::AppRecovery => "S02apprecover",
            Self::Ethernet => "S30eth",
            Self::Wifi => "S30wifi",
            Self::NanoKvm => "S95nanokvm",
        }
    }

    pub fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::AppRecovery => b"NKBSA001",
            Self::Ethernet => b"NKBSE001",
            Self::Wifi => b"NKBSW001",
            Self::NanoKvm => b"NKBSK001",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct InvalidBinding;

pub fn validate(bytes: &[u8], role: Role) -> Result<&[u8], InvalidBinding> {
    if bytes.len() < HEADER || &bytes[..8] != role.magic() {
        return Err(InvalidBinding);
    }
    let size = u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| InvalidBinding)?);
    if !(1..=MAX_SCRIPT as u64).contains(&size) || bytes.len() as u64 != HEADER as u64 + size {
        return Err(InvalidBinding);
    }
    let body = &bytes[HEADER..];
    let digest: [u8; 32] = bytes[16..HEADER].try_into().map_err(|_| InvalidBinding)?;
    if !body.starts_with(b"#!/bin/sh\n")
        || body.contains(&0)
        || <[u8; 32]>::from(Sha256::digest(body)) != digest
    {
        return Err(InvalidBinding);
    }
    Ok(body)
}
