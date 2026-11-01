//! Fixed host-key proof vocabulary. No caller-selected paths or commands.
use super::restore_ssh::SshRestoreError;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use zeroize::Zeroizing;

pub(super) const MAX_PUBLIC: usize = 16 * 1024;
pub(super) const NAMESPACE: &str = "hardened-nanokvm-restore-key-proof-v1";
pub(super) const PRINCIPAL: &str = "restore-probe";
pub(super) const CHALLENGE: &str = "/run/restore-key-challenge";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HostKey {
    Rsa,
    Ecdsa,
    Ed25519,
    Mldsa44Ed25519,
}
impl HostKey {
    pub const ALL: [Self; 4] = [Self::Rsa, Self::Ecdsa, Self::Ed25519, Self::Mldsa44Ed25519];
    pub fn private_path(self) -> &'static str {
        match self {
            Self::Rsa => "/etc/ssh/ssh_host_rsa_key",
            Self::Ecdsa => "/etc/ssh/ssh_host_ecdsa_key",
            Self::Ed25519 => "/etc/ssh/ssh_host_ed25519_key",
            Self::Mldsa44Ed25519 => "/etc/ssh/ssh_host_mldsa44_ed25519_key",
        }
    }
    /// OpenSSH 10.6 renamed this type and reads no key of the old name, which
    /// `ssh-keygen -A` left on every system up to 0.3.0-raw.12.
    fn retired_type(self) -> Option<&'static [u8]> {
        match self {
            Self::Mldsa44Ed25519 => Some(b"ssh-mldsa44-ed25519@openssh.com"),
            Self::Rsa | Self::Ecdsa | Self::Ed25519 => None,
        }
    }
    pub(super) fn signature_path(self) -> &'static str {
        match self {
            Self::Rsa => "/run/restore-rsa.sig",
            Self::Ecdsa => "/run/restore-ecdsa.sig",
            Self::Ed25519 => "/run/restore-ed25519.sig",
            Self::Mldsa44Ed25519 => "/run/restore-mldsa44-ed25519.sig",
        }
    }
    pub(super) fn allowed_path(self) -> &'static str {
        match self {
            Self::Rsa => "/run/restore-rsa.allowed",
            Self::Ecdsa => "/run/restore-ecdsa.allowed",
            Self::Ed25519 => "/run/restore-ed25519.allowed",
            Self::Mldsa44Ed25519 => "/run/restore-mldsa44-ed25519.allowed",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyStage {
    Public,
    Sign,
    Verify,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyOperation {
    pub key: HostKey,
    pub stage: KeyStage,
}
impl KeyOperation {
    pub fn parse(value: &str) -> Option<Self> {
        let (stage, key) = value.split_once(':')?;
        Some(Self {
            key: match key {
                "rsa" => HostKey::Rsa,
                "ecdsa" => HostKey::Ecdsa,
                "ed25519" => HostKey::Ed25519,
                "mldsa44-ed25519" => HostKey::Mldsa44Ed25519,
                _ => return None,
            },
            stage: match stage {
                "public" => KeyStage::Public,
                "sign" => KeyStage::Sign,
                "verify" => KeyStage::Verify,
                _ => return None,
            },
        })
    }
    pub fn as_argument(self) -> &'static str {
        match (self.stage, self.key) {
            (KeyStage::Public, HostKey::Rsa) => "public:rsa",
            (KeyStage::Public, HostKey::Ecdsa) => "public:ecdsa",
            (KeyStage::Public, HostKey::Ed25519) => "public:ed25519",
            (KeyStage::Public, HostKey::Mldsa44Ed25519) => "public:mldsa44-ed25519",
            (KeyStage::Sign, HostKey::Rsa) => "sign:rsa",
            (KeyStage::Sign, HostKey::Ecdsa) => "sign:ecdsa",
            (KeyStage::Sign, HostKey::Ed25519) => "sign:ed25519",
            (KeyStage::Sign, HostKey::Mldsa44Ed25519) => "sign:mldsa44-ed25519",
            (KeyStage::Verify, HostKey::Rsa) => "verify:rsa",
            (KeyStage::Verify, HostKey::Ecdsa) => "verify:ecdsa",
            (KeyStage::Verify, HostKey::Ed25519) => "verify:ed25519",
            (KeyStage::Verify, HostKey::Mldsa44Ed25519) => "verify:mldsa44-ed25519",
        }
    }
    pub(super) fn native_arguments(self) -> Vec<&'static str> {
        match self.stage {
            KeyStage::Public => vec![
                "/usr/bin/ssh-keygen",
                "-y",
                "-P",
                "",
                "-f",
                self.key.private_path(),
            ],
            KeyStage::Sign => vec![
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-q",
                "-n",
                NAMESPACE,
                "-P",
                "",
                "-f",
                self.key.private_path(),
            ],
            KeyStage::Verify => vec![
                "/usr/bin/ssh-keygen",
                "-Y",
                "verify",
                "-q",
                "-n",
                NAMESPACE,
                "-I",
                PRINCIPAL,
                "-f",
                self.key.allowed_path(),
                "-s",
                self.key.signature_path(),
            ],
        }
    }
}

pub(super) struct PublicIdentity {
    pub(super) kind: &'static str,
    pub(super) blob: Zeroizing<Vec<u8>>,
}
impl PublicIdentity {
    pub(super) fn allowed_signers(&self) -> Zeroizing<String> {
        // Decoded input was <=16KiB base64; reserve before formatting once.
        let mut result = Zeroizing::new(String::with_capacity(MAX_PUBLIC + 128));
        result.push_str(PRINCIPAL);
        result.push(' ');
        result.push_str(self.kind);
        result.push(' ');
        STANDARD.encode_string(&self.blob, &mut result);
        result.push('\n');
        result
    }
}

fn key_fields(bytes: &[u8]) -> Option<impl Iterator<Item = &[u8]>> {
    let line = bytes.split(|b| *b == b'\n').find(|line| {
        let line = line.trim_ascii();
        !line.is_empty() && !line.starts_with(b"#")
    })?;
    Some(
        line.split(u8::is_ascii_whitespace)
            .filter(|s| !s.is_empty()),
    )
}

/// Whether a public key file names a type no program in the image can load.
pub(super) fn retired_public(bytes: &[u8], algorithm: HostKey) -> bool {
    key_fields(bytes)
        .and_then(|mut fields| fields.next())
        .is_some_and(|kind| Some(kind) == algorithm.retired_type())
}

pub(super) fn parse_public(
    bytes: &[u8],
    algorithm: HostKey,
) -> Result<PublicIdentity, SshRestoreError> {
    if bytes.is_empty() || bytes.len() > MAX_PUBLIC || bytes.contains(&0) {
        return Err(SshRestoreError::InvalidKey);
    }
    let mut fields = key_fields(bytes).ok_or(SshRestoreError::InvalidKey)?;
    let kind = fields.next().ok_or(SshRestoreError::InvalidKey)?;
    let encoded = fields.next().ok_or(SshRestoreError::InvalidKey)?;
    let kind = match (algorithm, kind) {
        (HostKey::Rsa, b"ssh-rsa") => "ssh-rsa",
        (HostKey::Ed25519, b"ssh-ed25519") => "ssh-ed25519",
        (HostKey::Mldsa44Ed25519, b"ssh-mldsa44-ed25519") => "ssh-mldsa44-ed25519",
        (HostKey::Ecdsa, b"ecdsa-sha2-nistp256") => "ecdsa-sha2-nistp256",
        (HostKey::Ecdsa, b"ecdsa-sha2-nistp384") => "ecdsa-sha2-nistp384",
        (HostKey::Ecdsa, b"ecdsa-sha2-nistp521") => "ecdsa-sha2-nistp521",
        _ => return Err(SshRestoreError::InvalidKey),
    };
    let mut blob = Zeroizing::new(vec![0; encoded.len() / 4 * 3 + 3]);
    let length = STANDARD
        .decode_slice(encoded, &mut blob)
        .or_else(|_| STANDARD_NO_PAD.decode_slice(encoded, &mut blob))
        .map_err(|_| SshRestoreError::InvalidKey)?;
    blob.truncate(length);
    let prefix: [u8; 4] = blob
        .get(..4)
        .ok_or(SshRestoreError::InvalidKey)?
        .try_into()
        .map_err(|_| SshRestoreError::InvalidKey)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if blob.get(
        4..4_usize
            .checked_add(length)
            .ok_or(SshRestoreError::InvalidKey)?,
    ) != Some(kind.as_bytes())
    {
        return Err(SshRestoreError::InvalidKey);
    }
    Ok(PublicIdentity { kind, blob })
}
