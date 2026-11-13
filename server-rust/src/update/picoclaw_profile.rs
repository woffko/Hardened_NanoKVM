//! Agent profile selection for the broker's Profile job. Pure: callers pass
//! the shipped profile documents and the workspace's current AGENT.md. Only an
//! absent document or an exact shipped profile is replaced; anything else is
//! the user's own and is kept.
use serde_json::Value as JsonValue;
use std::path::{Path, PathBuf};

/// Fixed directory of the shipped profile documents.
pub(crate) const SHIPPED: &str = "/kvmapp/picoclaw";
/// The profile document inside the workspace.
pub(crate) const AGENT: &str = "AGENT.md";
pub(crate) const MAX_PROFILE_BYTES: usize = 64 * 1024;
#[cfg(test)]
pub(crate) const SHIPPED_AGENT: &[u8] = include_bytes!("../../../kvmapp/picoclaw/AGENT.md");
#[cfg(test)]
pub(crate) const SHIPPED_AGENT_KVM: &[u8] = include_bytes!("../../../kvmapp/picoclaw/AGENT_KVM.md");
pub(crate) const PRIOR_SHIPPED: [[u8; 32]; 1] = [[
    0xcd, 0xf2, 0x0e, 0xfa, 0x3f, 0x7e, 0x4f, 0x60, 0xad, 0x68, 0x57, 0x31, 0x79, 0x5e, 0x00, 0x45,
    0xf7, 0x2c, 0xf5, 0x4f, 0x45, 0x52, 0x02, 0xa1, 0x41, 0xac, 0x6a, 0xf0, 0xe1, 0x6c, 0xc2, 0x30,
]];

pub(crate) fn is_prior_shipped(bytes: &[u8]) -> bool {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    PRIOR_SHIPPED
        .iter()
        .any(|prior| prior.as_slice() == digest.as_slice())
}

/// Whether a Startup job puts the shipped profile in place of `current`. It fills
/// a workspace without a profile and retires a superseded shipped document. Any
/// other profile stands, the default included: that is what the user selected.
pub(crate) fn settles(current: Option<&[u8]>) -> bool {
    current.is_none_or(is_prior_shipped)
}

/// The shipped document for the default or the KVM profile.
pub(crate) fn shipped_name(kvm: bool) -> &'static str {
    if kvm { "AGENT_KVM.md" } else { "AGENT.md" }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    /// The workspace already holds the requested profile.
    Noop,
    /// Absent, or exactly one of the shipped profiles: replace it.
    Replace,
    /// A customized document: it is kept and the request refused.
    Custom,
}

pub(crate) fn classify(current: Option<&[u8]>, desired: &[u8], shipped: [&[u8]; 2]) -> Decision {
    match current {
        Some(current) if current == desired => Decision::Noop,
        None => Decision::Replace,
        Some(current) if shipped.contains(&current) => Decision::Replace,
        Some(_) => Decision::Custom,
    }
}

/// The workspace a config selects: `agents.defaults.workspace`, with `~`
/// standing for /root, or else `<home>/workspace`. A relative selection has
/// no fixed meaning for the broker and is `None`.
pub(crate) fn workspace(config: &JsonValue, home: &Path) -> Option<PathBuf> {
    let selected = config
        .pointer("/agents/defaults/workspace")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|path| !path.is_empty());
    let path = match selected {
        None => home.join("workspace"),
        Some("~") => PathBuf::from("/root"),
        Some(path) => match path.strip_prefix("~/") {
            Some(rest) => Path::new("/root").join(rest),
            None => PathBuf::from(path),
        },
    };
    path.is_absolute().then_some(path)
}

#[cfg(test)]
#[path = "picoclaw_profile_tests.rs"]
mod tests;
