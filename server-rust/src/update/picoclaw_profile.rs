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
