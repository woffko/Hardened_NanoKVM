//! Explicit build compatibility declarations, NOT provenance or capabilities.
//!
//! Matching bytes never authorize execution or a support-file transition. In
//! particular, two declarations with transition epoch zero remain unsupported.

use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 8] = b"NKABICAP";
pub const BYTES: usize = 128;
const PREFIX: usize = 96;
const FORMAT: u16 = 1;
const DOMAIN: &[u8] = b"NanoKVM support ABI descriptor v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Role {
    Backend = 1,
    AppRecovery = 2,
    NativeOwner = 3,
    NativeBroker = 4,
    NativeClient = 5,
    NativeRecovery = 6,
}

pub const ROLES: [Role; 6] = [
    Role::Backend,
    Role::AppRecovery,
    Role::NativeOwner,
    Role::NativeBroker,
    Role::NativeClient,
    Role::NativeRecovery,
];

impl Role {
    pub fn filename(self) -> &'static str {
        match self {
            Self::Backend => "nanokvm-rust-server",
            Self::AppRecovery => "nanokvm-app-recovery",
            Self::NativeOwner => "nanokvm-native-owner",
            Self::NativeBroker => "nanokvm-native-broker",
            Self::NativeClient => "nanokvm-native-ctl",
            Self::NativeRecovery => "nanokvm-native-recovery",
        }
    }
}

/// Group epochs describe coherent source semantics, not command privileges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Epochs {
    /// App record, recovery intent, history, payload/receipt GC and ordering.
    pub app_storage: u32,
    /// Native/boot journals, scope lifetime, broker/trial/lease protocols.
    pub native_lifecycle: u32,
    pub helper_framing: u32,
    pub boot_script_framing: u32,
    /// Zero until stage/swap/rollback/settlement AND early recovery exist.
    pub support_transition: u32,
}

// This is an explicit declaration by this source, not an inference from old
// journal magic suffixes. Do not advertise transition support from parsing alone.
pub const CURRENT: Epochs = Epochs {
    app_storage: 1,
    native_lifecycle: 3,
    helper_framing: 1,
    boot_script_framing: 1,
    support_transition: 0,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Declaration {
    pub role: Role,
    pub epochs: Epochs,
}

#[derive(Debug, Eq, PartialEq)]
pub struct InvalidDeclaration;

fn hash(prefix: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(prefix);
    hash.finalize().into()
}

/// Fixed current declaration. There is no path, executable or epoch override.
pub fn encode(role: Role) -> [u8; BYTES] {
    let mut bytes = [0; BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&FORMAT.to_le_bytes());
    bytes[10..12].copy_from_slice(&(BYTES as u16).to_le_bytes());
    bytes[12] = role as u8;
    for (index, epoch) in [
        CURRENT.app_storage,
        CURRENT.native_lifecycle,
        CURRENT.helper_framing,
        CURRENT.boot_script_framing,
        CURRENT.support_transition,
    ]
    .into_iter()
    .enumerate()
    {
        let offset = 16 + index * 4;
        bytes[offset..offset + 4].copy_from_slice(&epoch.to_le_bytes());
    }
    let digest = hash(&bytes[..PREFIX]);
    bytes[PREFIX..].copy_from_slice(&digest);
    bytes
}

/// Distinguish invalid marker literals from checksum-valid unknown declarations.
/// The latter must fail strict decoding, not be skipped for a later good frame.
pub fn checksummed(bytes: &[u8]) -> bool {
    bytes.len() == BYTES && &bytes[..8] == MAGIC && bytes[PREFIX..] == hash(&bytes[..PREFIX])
}

/// Unknown group epochs are preserved for diagnostics, never silently omitted.
/// Compatibility and a retained installation capability are separate checks.
pub fn decode(bytes: &[u8]) -> Result<Declaration, InvalidDeclaration> {
    if !checksummed(bytes)
        || bytes[8..10] != FORMAT.to_le_bytes()
        || bytes[10..12] != (BYTES as u16).to_le_bytes()
        || bytes[13..16] != [0; 3]
        || bytes[36..PREFIX] != [0; PREFIX - 36]
    {
        return Err(InvalidDeclaration);
    }
    let role = ROLES
        .into_iter()
        .find(|role| *role as u8 == bytes[12])
        .ok_or(InvalidDeclaration)?;
    let mut epochs = [0; 5];
    for (epoch, encoded) in epochs.iter_mut().zip(bytes[16..36].as_chunks::<4>().0) {
        *epoch = u32::from_le_bytes(*encoded);
    }
    Ok(Declaration {
        role,
        epochs: Epochs {
            app_storage: epochs[0],
            native_lifecycle: epochs[1],
            helper_framing: epochs[2],
            boot_script_framing: epochs[3],
            support_transition: epochs[4],
        },
    })
}

#[cfg(test)]
#[path = "support_abi_tests.rs"]
mod tests;
