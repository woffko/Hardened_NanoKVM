//! Private fixed-schema support plan. A checksum/layout is never authority.
use super::*;

pub(super) const BYTES: usize = 2048;
const PREFIX: usize = BYTES - 32;
const MAGIC: &[u8; 8] = b"NKSPRT01";
const DOMAIN: &[u8] = b"NanoKVM app support transaction v1\0";
const APP: std::ops::Range<usize> = 16..528;
const PARENTS: usize = 528;
const OBJECTS: usize = 640;
const OBJECT_BYTES: usize = 72;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Phase {
    Staging = 1,
    Ready = 2,
    CleanupOld = 3,
    CleanupNew = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Object {
    pub(super) identity: Identity,
    pub(super) size: u64,
    pub(super) mode: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Entry {
    pub(super) old: Object,
    pub(super) new: Object,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct Plan {
    pub(super) phase: Phase,
    // Canonical app record normalized to Prepared. No caller-supplied ID or
    // checksum can substitute for the retained store/accepted install owner.
    pub(super) app: Record,
    pub(super) parents: [Identity; 7],
    pub(super) entries: [Entry; COUNT],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Placement {
    OldNew,
    NewOld,
    OldMissing,
    NewMissing,
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}

impl Plan {
    pub(super) fn validate(&self, uid: u32, gid: u32) -> Result<()> {
        self.app.validate()?;
        if self.app.phase != super::super::Phase::Prepared {
            return Err(SlotError::Invalid);
        }
        let device = self.app.old.device;
        for (index, identity) in self.parents.iter().enumerate() {
            if identity.device != device
                || identity.inode == 0
                || self.parents[..index].contains(identity)
                || [self.app.old, self.app.new].contains(identity)
            {
                return Err(SlotError::Invalid);
            }
        }
        let mut identities = [None; COUNT * 2];
        for (index, entry) in self.entries.iter().enumerate() {
            for (side, object) in [entry.old, entry.new].into_iter().enumerate() {
                let slot = index * 2 + side;
                if object.identity.device != device
                    || object.identity.inode == 0
                    || object.size == 0
                    || object.size > maximum(index)
                    || object.mode != 0o755
                    || object.uid != uid
                    || object.gid != gid
                    || identities[..slot].contains(&Some(object.identity))
                    || self.parents.contains(&object.identity)
                    || [self.app.old, self.app.new].contains(&object.identity)
                {
                    return Err(SlotError::Invalid);
                }
                identities[slot] = Some(object.identity);
            }
        }
        Ok(())
    }

    pub(super) fn encode(&self, uid: u32, gid: u32) -> Result<[u8; BYTES]> {
        self.validate(uid, gid)?;
        let mut bytes = [0; BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = self.phase as u8;
        bytes[APP].copy_from_slice(&self.app.encode()?);
        for (index, identity) in self.parents.iter().enumerate() {
            let offset = PARENTS + index * 16;
            bytes[offset..offset + 8].copy_from_slice(&identity.device.to_le_bytes());
            bytes[offset + 8..offset + 16].copy_from_slice(&identity.inode.to_le_bytes());
        }
        for (index, entry) in self.entries.iter().enumerate() {
            for (side, object) in [entry.old, entry.new].into_iter().enumerate() {
                let start = OBJECTS + (index * 2 + side) * OBJECT_BYTES;
                let out = &mut bytes[start..start + OBJECT_BYTES];
                for (offset, value) in [
                    (0, object.identity.device),
                    (8, object.identity.inode),
                    (16, object.size),
                ] {
                    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
                }
                for (offset, value) in [(24, object.mode), (28, object.uid), (32, object.gid)] {
                    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
                }
                out[40..72].copy_from_slice(&object.sha256);
            }
        }
        let hash = digest(&bytes[..PREFIX]);
        bytes[PREFIX..].copy_from_slice(&hash);
        Ok(bytes)
    }

    pub(super) fn decode(bytes: &[u8], uid: u32, gid: u32) -> Result<Self> {
        if bytes.len() != BYTES
            || &bytes[..8] != MAGIC
            || bytes[9..16] != [0; 7]
            || bytes[1936..PREFIX].iter().any(|byte| *byte != 0)
            || bytes[PREFIX..] != digest(&bytes[..PREFIX])
        {
            return Err(SlotError::Invalid);
        }
        let phase = match bytes[8] {
            1 => Phase::Staging,
            2 => Phase::Ready,
            3 => Phase::CleanupOld,
            4 => Phase::CleanupNew,
            _ => return Err(SlotError::Invalid),
        };
        let u64_at = |offset| {
            bytes[offset..offset + 8]
                .try_into()
                .map(u64::from_le_bytes)
                .map_err(|_| SlotError::Invalid)
        };
        let u32_at = |offset| {
            bytes[offset..offset + 4]
                .try_into()
                .map(u32::from_le_bytes)
                .map_err(|_| SlotError::Invalid)
        };
        let identity = |offset| -> Result<Identity> {
            Ok(Identity {
                device: u64_at(offset)?,
                inode: u64_at(offset + 8)?,
            })
        };
        let mut parents = [Identity {
            device: 0,
            inode: 0,
        }; 7];
        for (index, parent) in parents.iter_mut().enumerate() {
            *parent = identity(PARENTS + index * 16)?;
        }
        let object = |offset| -> Result<Object> {
            if bytes[offset + 36..offset + 40] != [0; 4] {
                return Err(SlotError::Invalid);
            }
            Ok(Object {
                identity: identity(offset)?,
                size: u64_at(offset + 16)?,
                mode: u32_at(offset + 24)?,
                uid: u32_at(offset + 28)?,
                gid: u32_at(offset + 32)?,
                sha256: bytes[offset + 40..offset + 72]
                    .try_into()
                    .map_err(|_| SlotError::Invalid)?,
            })
        };
        let first = Entry {
            old: object(OBJECTS)?,
            new: object(OBJECTS + OBJECT_BYTES)?,
        };
        let mut entries = [first; COUNT];
        for (index, entry) in entries.iter_mut().enumerate().skip(1) {
            let offset = OBJECTS + index * OBJECT_BYTES * 2;
            *entry = Entry {
                old: object(offset)?,
                new: object(offset + OBJECT_BYTES)?,
            };
        }
        let plan = Self {
            phase,
            app: Record::decode(&bytes[APP])?,
            parents,
            entries,
        };
        plan.validate(uid, gid)?;
        Ok(plan)
    }

    /// Pure classification only. The caller must still prove exact inode,
    /// metadata/content, canonical app state and retained native/writer closure.
    pub(super) fn check_layout(
        &self,
        app: super::super::Phase,
        placements: &[Placement; COUNT],
    ) -> Result<()> {
        let valid = match self.phase {
            Phase::Staging => {
                app == super::super::Phase::Prepared
                    && placements
                        .iter()
                        .all(|p| matches!(p, Placement::OldNew | Placement::OldMissing))
            }
            Phase::Ready => placements
                .iter()
                .all(|p| matches!(p, Placement::OldNew | Placement::NewOld)),
            Phase::CleanupOld => {
                app == super::super::Phase::RolledBack
                    && placements
                        .iter()
                        .all(|p| matches!(p, Placement::OldNew | Placement::OldMissing))
            }
            Phase::CleanupNew => {
                app == super::super::Phase::Committed
                    && placements
                        .iter()
                        .all(|p| matches!(p, Placement::NewOld | Placement::NewMissing))
            }
        };
        if valid {
            Ok(())
        } else {
            Err(SlotError::Invalid)
        }
    }
}
