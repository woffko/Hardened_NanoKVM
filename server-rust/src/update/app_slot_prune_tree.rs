//! Bounded immutable deletion inventory; this module grants no prune authority.
use super::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    os::unix::ffi::OsStringExt,
    path::PathBuf,
};

const MAX_NODES: usize = 8193;
const MAX_PATH_BYTES: usize = 32 * 1024 * 1024;
const MAX_PAYLOAD: u64 = 256 * 1024 * 1024 + 64 * 1024;
const HEADER: usize = 528;
const NODE_BYTES: usize = 56;
pub(super) const MAX_MANIFEST: u64 = 34 * 1024 * 1024;

#[derive(Clone, Eq, PartialEq)]
pub(super) struct Node {
    pub path: PathBuf,
    pub directory: bool,
    depth: u8,
    mode: u32,
    pub identity: Identity,
    pub parent: Identity,
    size: u64,
}

fn compare(a: &Node, b: &Node) -> std::cmp::Ordering {
    b.depth.cmp(&a.depth).then_with(|| a.path.cmp(&b.path))
}

pub(super) fn open_path(parent: &File, path: &Path, flags: OFlags) -> Result<File> {
    Ok(openat2(
        parent,
        path,
        flags | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )?
    .into())
}

fn node(file: &File, parent: Identity, path: PathBuf, device: u64, uid: u32) -> Result<Node> {
    let m = file.metadata()?;
    let depth = path.components().count();
    if m.dev() != device
        || m.uid() != uid
        || m.ino() == 0
        || m.mode() & 0o7022 != 0
        || (!m.is_file() && !m.is_dir())
        || (m.is_file() && m.nlink() != 1)
        || depth > 64
        || path.as_os_str().len() > 4096
    {
        return Err(SlotError::Unsafe);
    }
    Ok(Node {
        path,
        directory: m.is_dir(),
        depth: depth as u8,
        mode: m.mode() & 0o7777,
        identity: Identity {
            device: m.dev(),
            inode: m.ino(),
        },
        parent,
        size: if m.is_file() { m.len() } else { 0 },
    })
}

struct Budget {
    paths: usize,
    bytes: u64,
}

fn walk(
    directory: &File,
    parent: Identity,
    path: PathBuf,
    device: u64,
    uid: u32,
    nodes: &mut Vec<Node>,
    budget: &mut Budget,
) -> Result<()> {
    let current = node(directory, parent, path, device, uid)?;
    if !current.directory || nodes.len() >= MAX_NODES {
        return Err(SlotError::Invalid);
    }
    budget.paths = budget
        .paths
        .checked_add(current.path.as_os_str().len())
        .filter(|n| *n <= MAX_PATH_BYTES)
        .ok_or(SlotError::Invalid)?;
    let identity = current.identity;
    let base = current.path.clone();
    nodes.push(current);
    for entry in rustix::fs::Dir::read_from(directory)? {
        let entry = entry?;
        if matches!(entry.file_name().to_bytes(), b"." | b"..") {
            continue;
        }
        if nodes.len() >= MAX_NODES {
            return Err(SlotError::Invalid);
        }
        let child = open_path(
            directory,
            Path::new(std::ffi::OsStr::from_bytes(entry.file_name().to_bytes())),
            OFlags::PATH,
        )?;
        let child_path = base.join(std::ffi::OsStr::from_bytes(entry.file_name().to_bytes()));
        let candidate = node(&child, identity, child_path, device, uid)?;
        let named = statat(directory, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW)?;
        if (named.st_dev, named.st_ino) != (candidate.identity.device, candidate.identity.inode) {
            return Err(SlotError::Unsafe);
        }
        if candidate.directory {
            let child = open_path(
                directory,
                Path::new(std::ffi::OsStr::from_bytes(entry.file_name().to_bytes())),
                OFlags::RDONLY | OFlags::DIRECTORY,
            )?;
            if Identity::of(&child, device, uid)? != candidate.identity {
                return Err(SlotError::Unsafe);
            }
            walk(&child, identity, candidate.path, device, uid, nodes, budget)?;
        } else {
            budget.paths = budget
                .paths
                .checked_add(candidate.path.as_os_str().len())
                .filter(|n| *n <= MAX_PATH_BYTES)
                .ok_or(SlotError::Invalid)?;
            budget.bytes = budget
                .bytes
                .checked_add(candidate.size)
                .filter(|n| *n <= MAX_PAYLOAD)
                .ok_or(SlotError::Invalid)?;
            nodes.push(candidate);
        }
    }
    Ok(())
}

pub(super) fn collect(
    directory: &File,
    parent: Identity,
    device: u64,
    uid: u32,
) -> Result<Vec<Node>> {
    let mut nodes = Vec::with_capacity(MAX_NODES);
    walk(
        directory,
        parent,
        PathBuf::new(),
        device,
        uid,
        &mut nodes,
        &mut Budget { paths: 0, bytes: 0 },
    )?;
    nodes.sort_unstable_by(compare);
    validate(&nodes, parent, device)?;
    Ok(nodes)
}

// Verify against borrowed manifest paths rather than allocating a second full
// path inventory (the admitted format permits up to32MiB of path bytes).
struct Verification<'a> {
    expected: BTreeMap<&'a Path, &'a Node>,
    seen: BTreeSet<&'a Path>,
    device: u64,
    uid: u32,
}

impl Verification<'_> {
    fn walk(&mut self, directory: &File, parent: Identity, path: PathBuf) -> Result<()> {
        let actual = node(directory, parent, path, self.device, self.uid)?;
        let expected = *self
            .expected
            .get(actual.path.as_path())
            .ok_or(SlotError::Unsafe)?;
        if actual != *expected || !self.seen.insert(expected.path.as_path()) {
            return Err(SlotError::Unsafe);
        }
        for entry in rustix::fs::Dir::read_from(directory)? {
            let entry = entry?;
            if matches!(entry.file_name().to_bytes(), b"." | b"..") {
                continue;
            }
            let name = Path::new(std::ffi::OsStr::from_bytes(entry.file_name().to_bytes()));
            let child = open_path(directory, name, OFlags::PATH)?;
            let actual_child = node(
                &child,
                actual.identity,
                actual.path.join(name),
                self.device,
                self.uid,
            )?;
            let expected = *self
                .expected
                .get(actual_child.path.as_path())
                .ok_or(SlotError::Unsafe)?;
            if actual_child != *expected {
                return Err(SlotError::Unsafe);
            }
            if actual_child.directory {
                let child = open_path(directory, name, OFlags::RDONLY | OFlags::DIRECTORY)?;
                self.walk(&child, actual.identity, actual_child.path)?;
            } else if !self.seen.insert(expected.path.as_path()) {
                return Err(SlotError::Unsafe);
            }
        }
        Ok(())
    }
}

pub(super) fn verify(
    directory: Option<&File>,
    parent: Identity,
    expected: &[Node],
    uid: u32,
    allow_missing_first: bool,
) -> Result<()> {
    let mut check = Verification {
        expected: expected
            .iter()
            .map(|node| (node.path.as_path(), node))
            .collect(),
        seen: BTreeSet::new(),
        device: parent.device,
        uid,
    };
    if let Some(directory) = directory {
        check.walk(directory, parent, PathBuf::new())?;
    }
    if check.seen.len() == expected.len()
        || (allow_missing_first
            && check.seen.len() + 1 == expected.len()
            && !check.seen.contains(expected[0].path.as_path()))
    {
        Ok(())
    } else {
        Err(SlotError::Unsafe)
    }
}

fn validate(nodes: &[Node], parent: Identity, device: u64) -> Result<()> {
    if nodes.is_empty() || nodes.len() > MAX_NODES {
        return Err(SlotError::Invalid);
    }
    let mut paths = 0_usize;
    let mut bytes = 0_u64;
    let mut identities = BTreeSet::new();
    let mut by_path = BTreeMap::new();
    for (index, node) in nodes.iter().enumerate() {
        let name = node.path.as_os_str().as_bytes();
        if node.identity.device != device
            || node.identity.inode == 0
            || node.parent.device != device
            || node.parent.inode == 0
            || node.mode & !0o7777 != 0
            || node.mode & 0o7022 != 0
            || name.len() > 4096
            || node.depth > 64
            || usize::from(node.depth) != node.path.components().count()
            || (node.directory && node.size != 0)
            || (!name.is_empty()
                && name.split(|b| *b == b'/').any(|part| {
                    part.is_empty() || part == b"." || part == b".." || part.contains(&0)
                }))
            || (name.is_empty() && (!node.directory || index + 1 != nodes.len()))
            || (index > 0 && compare(&nodes[index - 1], node) != std::cmp::Ordering::Less)
            || !identities.insert((node.identity.device, node.identity.inode))
            || by_path.insert(node.path.as_path(), node).is_some()
        {
            return Err(SlotError::Invalid);
        }
        paths = paths
            .checked_add(name.len())
            .filter(|n| *n <= MAX_PATH_BYTES)
            .ok_or(SlotError::Invalid)?;
        bytes = bytes
            .checked_add(node.size)
            .filter(|n| *n <= MAX_PAYLOAD)
            .ok_or(SlotError::Invalid)?;
    }
    if !nodes
        .last()
        .is_some_and(|n| n.path.as_os_str().is_empty() && n.parent == parent)
    {
        return Err(SlotError::Invalid);
    }
    for node in nodes.iter().filter(|n| !n.path.as_os_str().is_empty()) {
        let parent = by_path
            .get(node.path.parent().ok_or(SlotError::Invalid)?)
            .ok_or(SlotError::Invalid)?;
        if !parent.directory || parent.identity != node.parent {
            return Err(SlotError::Invalid);
        }
    }
    Ok(())
}

pub(super) struct Manifest {
    pub owner: Order,
    pub victim: Order,
    pub nodes: Vec<Node>,
    pub hash: [u8; 32],
}

fn hasher() -> Sha256 {
    let mut hash = Sha256::new();
    hash.update(b"NanoKVM app prune inventory v1\0");
    hash
}

fn write_hashed(output: &mut impl Write, hash: &mut Sha256, bytes: &[u8]) -> Result<()> {
    output.write_all(bytes)?;
    hash.update(bytes);
    Ok(())
}

fn read_hashed<const N: usize>(input: &mut File, hash: &mut Sha256) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    input.read_exact(&mut bytes)?;
    hash.update(bytes);
    Ok(bytes)
}

impl Manifest {
    pub fn new(owner: Order, victim: Order, nodes: Vec<Node>) -> Result<Self> {
        let mut manifest = Self {
            owner,
            victim,
            nodes,
            hash: [0; 32],
        };
        manifest.hash = manifest.encode(&mut io::sink())?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<()> {
        self.owner.validate(self.owner.directory.device)?;
        self.victim.validate(self.owner.directory.device)?;
        if self.owner.sequence <= self.victim.sequence
            || self.owner.transaction == self.victim.transaction
            || self.owner.directory == self.victim.directory
        {
            return Err(SlotError::Invalid);
        }
        validate(
            &self.nodes,
            self.victim.directory,
            self.owner.directory.device,
        )
    }

    pub fn encode(&self, output: &mut impl Write) -> Result<[u8; 32]> {
        self.validate()?;
        let mut hash = hasher();
        let mut header = [0; HEADER];
        header[..8].copy_from_slice(b"NKAPPM01");
        header[8..264].copy_from_slice(&self.owner.encode()?);
        header[264..520].copy_from_slice(&self.victim.encode()?);
        header[520..524].copy_from_slice(&(self.nodes.len() as u32).to_le_bytes());
        write_hashed(output, &mut hash, &header)?;
        for node in &self.nodes {
            let mut bytes = [0; NODE_BYTES];
            bytes[0] = if node.directory { 2 } else { 1 };
            bytes[1] = node.depth;
            bytes[2..4].copy_from_slice(&(node.path.as_os_str().len() as u16).to_le_bytes());
            bytes[4..8].copy_from_slice(&node.mode.to_le_bytes());
            for (offset, value) in [
                (8, node.identity.device),
                (16, node.identity.inode),
                (24, node.parent.device),
                (32, node.parent.inode),
                (40, node.size),
            ] {
                bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            }
            write_hashed(output, &mut hash, &bytes)?;
            write_hashed(output, &mut hash, node.path.as_os_str().as_bytes())?;
        }
        let digest: [u8; 32] = hash.finalize().into();
        output.write_all(&digest)?;
        Ok(digest)
    }

    pub fn read(file: &mut File, device: u64) -> Result<Self> {
        let mut hash = hasher();
        let header: [u8; HEADER] = read_hashed(file, &mut hash)?;
        if &header[..8] != b"NKAPPM01" || header[524..] != [0; 4] {
            return Err(SlotError::Invalid);
        }
        let count = u32::from_le_bytes(
            header[520..524]
                .try_into()
                .map_err(|_| SlotError::Invalid)?,
        ) as usize;
        if count == 0 || count > MAX_NODES {
            return Err(SlotError::Invalid);
        }
        let mut nodes = Vec::with_capacity(count);
        let mut paths = 0_usize;
        for _ in 0..count {
            let bytes: [u8; NODE_BYTES] = read_hashed(file, &mut hash)?;
            let number = |offset| {
                bytes[offset..offset + 8]
                    .try_into()
                    .map(u64::from_le_bytes)
                    .map_err(|_| SlotError::Invalid)
            };
            let length = usize::from(u16::from_le_bytes(
                bytes[2..4].try_into().map_err(|_| SlotError::Invalid)?,
            ));
            if length > 4096 || bytes[48..] != [0; 8] {
                return Err(SlotError::Invalid);
            }
            paths = paths
                .checked_add(length)
                .filter(|n| *n <= MAX_PATH_BYTES)
                .ok_or(SlotError::Invalid)?;
            let mut path = vec![0; length];
            file.read_exact(&mut path)?;
            hash.update(&path);
            nodes.push(Node {
                path: PathBuf::from(OsString::from_vec(path)),
                directory: match bytes[0] {
                    1 => false,
                    2 => true,
                    _ => return Err(SlotError::Invalid),
                },
                depth: bytes[1],
                mode: u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| SlotError::Invalid)?),
                identity: Identity {
                    device: number(8)?,
                    inode: number(16)?,
                },
                parent: Identity {
                    device: number(24)?,
                    inode: number(32)?,
                },
                size: number(40)?,
            });
        }
        let mut expected = [0; 32];
        file.read_exact(&mut expected)?;
        let actual: [u8; 32] = hash.finalize().into();
        if actual != expected || file.read(&mut [0])? != 0 {
            return Err(SlotError::Invalid);
        }
        let manifest = Self {
            owner: Order::decode(&header[8..264], device)?,
            victim: Order::decode(&header[264..520], device)?,
            nodes,
            hash: actual,
        };
        manifest.validate()?;
        Ok(manifest)
    }
}

pub(super) fn remove_node(
    archive: &File,
    quarantine: Option<&File>,
    node: &Node,
    uid: u32,
    allow_absent: bool,
) -> Result<()> {
    let root = node.path.as_os_str().is_empty();
    let parent = if root {
        archive.try_clone()?
    } else {
        let parent = node.path.parent().ok_or(SlotError::Invalid)?;
        let root = quarantine.ok_or(SlotError::Invalid)?;
        if parent.as_os_str().is_empty() {
            root.try_clone()?
        } else {
            open_path(root, parent, OFlags::RDONLY | OFlags::DIRECTORY)?
        }
    };
    if Identity::of(&parent, node.identity.device, uid)? != node.parent {
        return Err(SlotError::Invalid);
    }
    let name = if root {
        std::ffi::OsStr::new(QUARANTINE)
    } else {
        node.path.file_name().ok_or(SlotError::Invalid)?
    };
    let pinned = match open_path(&parent, Path::new(name), OFlags::PATH) {
        Ok(file) => Some(file),
        Err(SlotError::Io(error)) if allow_absent && error.kind() == io::ErrorKind::NotFound => {
            None
        }
        Err(error) => return Err(error),
    };
    if let Some(pinned) = pinned {
        if self::node(
            &pinned,
            node.parent,
            node.path.clone(),
            node.identity.device,
            uid,
        )? != *node
        {
            return Err(SlotError::Unsafe);
        }
        #[cfg(test)]
        point("prune-node-pinned")?;
        let named = statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if (named.st_dev, named.st_ino) != (node.identity.device, node.identity.inode) {
            return Err(SlotError::Unsafe);
        }
        rustix::fs::unlinkat(
            &parent,
            name,
            if node.directory {
                AtFlags::REMOVEDIR
            } else {
                AtFlags::empty()
            },
        )?;
        #[cfg(test)]
        point("prune-node-unlinked")?;
    }
    parent.sync_all()?;
    #[cfg(test)]
    point("prune-node-parent-synced")?;
    Ok(())
}
