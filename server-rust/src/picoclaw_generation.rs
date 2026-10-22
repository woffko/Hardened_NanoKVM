//! Private identity shared by configuration I/O and native process ownership.
//! Equality is not writer exclusion, readiness, native closure or provenance.
use sha2::{Digest, Sha256};

/// Identity of exact credential-bearing bytes. Never Debug/serialize/log it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Generation([u8; 32]);

impl Generation {
    pub(crate) fn from_pair(config: &[u8], security: Option<&[u8]>) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"NanoKVM picoclaw configuration generation v1\0");
        hash.update((config.len() as u64).to_le_bytes());
        hash.update(config);
        hash.update([u8::from(security.is_some())]);
        if let Some(security) = security {
            hash.update((security.len() as u64).to_le_bytes());
            hash.update(security);
        }
        Self(hash.finalize().into())
    }

    /// Only for the protected immutable job source, never public observations.
    pub(crate) fn private_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn fixture(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_pair_presence_and_boundaries_are_distinct_and_zero_is_not_absence() {
        assert!(
            Generation::from_pair(b"ab", Some(b"c")) != Generation::from_pair(b"a", Some(b"bc"))
        );
        assert!(Generation::from_pair(b"{}", None) != Generation::from_pair(b"{}", Some(b"")));
        assert!(Generation::from_pair(b"{}", None) != Generation::from_pair(b"{}\n", None));
        assert_eq!(Generation::fixture([0; 32]).private_bytes(), &[0; 32]);
    }
}
