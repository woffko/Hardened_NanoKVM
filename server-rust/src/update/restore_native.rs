//! Bounded native account validation and collision-free signed-image merge.
//! This module neither verifies the image signature nor applies live files.

use std::collections::BTreeSet;

use zeroize::Zeroizing;

use super::restore_archive::CanonicalSetting;

#[path = "restore_native_hash.rs"]
mod native_hash;

pub const MAX_TABLE_BYTES: usize = 64 * 1024;
const MAX_ROWS: usize = 512;
const MAX_LINE: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum NativeAccountError {
    #[error("native restore account tables are invalid or inconsistent")]
    Invalid,
    #[error("native restore account tables exceed their resource budget")]
    Limit,
    #[error(
        "native account IDs or signed service requirements conflict; explicit migration is required"
    )]
    Conflict,
    #[error("native restore account layout requires an explicit migration")]
    Unsupported,
}
type Result<T> = std::result::Result<T, NativeAccountError>;

/// Borrowed protected source files, or files extracted from the exact verified
/// signed rootfs. Never supply p3 markers or a pre-fakeroot Buildroot target tree
/// as the signed baseline. The caller owns signature/immutable-image proof.
pub struct AccountFiles<'a> {
    pub passwd: &'a [u8],
    pub group: &'a [u8],
    pub shadow: &'a [u8],
    pub gshadow: Option<&'a [u8]>,
}

// No Debug/Clone/serde: shadow contents remain in bounded zeroizing buffers.
pub struct MergedAccounts {
    passwd: Zeroizing<Vec<u8>>,
    group: Zeroizing<Vec<u8>>,
    shadow: Zeroizing<Vec<u8>>,
    gshadow: Option<Zeroizing<Vec<u8>>>,
}
impl MergedAccounts {
    pub(super) fn into_settings(self) -> [CanonicalSetting<'static>; 4] {
        [
            CanonicalSetting {
                path: "etc/passwd",
                bytes: Some(self.passwd),
            },
            CanonicalSetting {
                path: "etc/group",
                bytes: Some(self.group),
            },
            CanonicalSetting {
                path: "etc/shadow",
                bytes: Some(self.shadow),
            },
            CanonicalSetting {
                path: "etc/gshadow",
                bytes: self.gshadow,
            },
        ]
    }
}

struct Row<'a, const N: usize> {
    line: &'a str,
    fields: [&'a str; N],
}
struct Tables<'a> {
    passwd: Vec<Row<'a, 7>>,
    group: Vec<Row<'a, 4>>,
    shadow: Vec<Row<'a, 9>>,
    gshadow: Option<Vec<Row<'a, 4>>>,
}

pub fn validate(files: &AccountFiles<'_>) -> Result<()> {
    Tables::parse(files).map(|_| ())
}

/// The authenticated snapshot must already contain all signed-image account
/// requirements. Do not silently add missing service state during early apply.
pub fn check_for_image(files: &AccountFiles<'_>, signed: &AccountFiles<'_>) -> Result<()> {
    let merged = merge(files, signed)?;
    if merged.passwd.as_slice() != files.passwd
        || merged.group.as_slice() != files.group
        || merged.shadow.as_slice() != files.shadow
        || merged.gshadow.as_deref().map(|v| v.as_slice()) != files.gshadow
    {
        return Err(NativeAccountError::Conflict);
    }
    Ok(())
}

/// Keep root and the accounts people use, and take every service account from
/// the signed image. Deployed systems number the same services differently, and
/// removed packages leave rows behind, so a device's service rows that differ
/// from the image go first. Restored files are all root's, so nothing depends
/// on those numbers. Accounts of people are never renumbered and hashes are never
/// rehashed: a clash with one of them refuses the update.
pub fn merge(source: &AccountFiles<'_>, signed: &AccountFiles<'_>) -> Result<MergedAccounts> {
    let old = Tables::parse(source)?;
    let image = Tables::parse(signed)?;
    match without_replaced_services(source, &old, &image)? {
        Some(kept) => merge_into(&kept.files(), signed),
        None => merge_into(source, signed),
    }
}

// No Debug/Clone/serde, as for MergedAccounts.
struct KeptAccounts {
    passwd: Zeroizing<Vec<u8>>,
    group: Zeroizing<Vec<u8>>,
    shadow: Zeroizing<Vec<u8>>,
    gshadow: Option<Zeroizing<Vec<u8>>>,
}
impl KeptAccounts {
    fn files(&self) -> AccountFiles<'_> {
        AccountFiles {
            passwd: &self.passwd,
            group: &self.group,
            shadow: &self.shadow,
            gshadow: self.gshadow.as_deref().map(|v| v.as_slice()),
        }
    }
}

/// A locked, non-login row below the range of people is a service account; root
/// is neither, by `parse`. In this sshd `*` does not stop a key login, so the shell
/// and the lock alone do not make an account disposable. One that matches the image
/// stays; any other leaves, and the merge then adds the image's row. A group leaves
/// when no remaining account needs it and the image has no equal.
fn without_replaced_services(
    source: &AccountFiles<'_>,
    old: &Tables<'_>,
    image: &Tables<'_>,
) -> Result<Option<KeptAccounts>> {
    let mut users = BTreeSet::new();
    for row in &old.passwd {
        let name = row.fields[0];
        let auth = find(&old.shadow, name).ok_or(NativeAccountError::Invalid)?;
        if person_id(number(row.fields[2])?)
            || !non_login_shell(row.fields[6])
            || !(locked(row.fields[1]) || locked(auth.fields[1]))
        {
            continue;
        }
        let same = find(&image.passwd, name).is_some_and(|signed| {
            [2, 3, 5, 6]
                .iter()
                .all(|field| signed.fields[*field] == row.fields[*field])
        });
        if !same {
            users.insert(name);
        }
    }
    let mut groups = BTreeSet::new();
    for row in &old.group {
        let name = row.fields[0];
        let gid = number(row.fields[2])?;
        let needed = old.passwd.iter().any(|user| {
            !users.contains(user.fields[0]) && number(user.fields[3]).ok() == Some(gid)
        }) || !staying(row.fields[3], &users).is_empty();
        if !needed
            && !person_id(gid)
            && find(&image.group, name)
                .is_none_or(|signed| number(signed.fields[2]).ok() != Some(gid))
        {
            groups.insert(name);
        }
    }
    if users.is_empty() && groups.is_empty() {
        return Ok(None);
    }
    let keep_user = |out: &mut Vec<u8>, name: &str, line: &str| {
        if users.contains(name) {
            return Ok(());
        }
        append_line(out, line.as_bytes())
    };
    Ok(Some(KeptAccounts {
        passwd: rewrite(source.passwd, &old.passwd, |out, row| {
            keep_user(out, row.fields[0], row.line)
        })?,
        shadow: rewrite(source.shadow, &old.shadow, |out, row| {
            keep_user(out, row.fields[0], row.line)
        })?,
        group: rewrite(source.group, &old.group, |out, row| {
            if groups.contains(row.fields[0]) {
                return Ok(());
            }
            write_fields(out, &row.fields[..3], &staying(row.fields[3], &users))
        })?,
        gshadow: match (source.gshadow, &old.gshadow) {
            (Some(bytes), Some(rows)) => Some(rewrite(bytes, rows, |out, row| {
                if groups.contains(row.fields[0]) {
                    return Ok(());
                }
                let admins = staying(row.fields[2], &users).join(",");
                write_fields(
                    out,
                    &[row.fields[0], row.fields[1], &admins],
                    &staying(row.fields[3], &users),
                )
            })?),
            _ => None,
        },
    }))
}

/// Comments stay as they are; each row goes through `write`.
fn rewrite<const N: usize>(
    source: &[u8],
    rows: &[Row<'_, N>],
    mut write: impl FnMut(&mut Vec<u8>, &Row<'_, N>) -> Result<()>,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(MAX_TABLE_BYTES));
    let text = std::str::from_utf8(source).map_err(|_| NativeAccountError::Invalid)?;
    for chunk in text.split_inclusive('\n') {
        let line = chunk.strip_suffix('\n').unwrap_or(chunk);
        match rows.iter().find(|row| row.line == line) {
            Some(row) => write(&mut out, row)?,
            None => push(&mut out, chunk.as_bytes())?,
        }
    }
    Ok(out)
}

fn staying<'a>(field: &'a str, users: &BTreeSet<&str>) -> Vec<&'a str> {
    field
        .split(',')
        .filter(|member| !member.is_empty() && !users.contains(member))
        .collect()
}

fn merge_into(source: &AccountFiles<'_>, signed: &AccountFiles<'_>) -> Result<MergedAccounts> {
    let old = Tables::parse(source)?;
    let image = Tables::parse(signed)?;
    let mut passwd = bounded_copy(source.passwd)?;
    let mut shadow = bounded_copy(source.shadow)?;
    for row in &image.passwd {
        let name = row.fields[0];
        if let Some(existing) = find(&old.passwd, name) {
            let existing_auth = find(&old.shadow, name).ok_or(NativeAccountError::Invalid)?;
            let signed_auth = find(&image.shadow, name).ok_or(NativeAccountError::Invalid)?;
            if number(existing.fields[2])? != number(row.fields[2])?
                || number(existing.fields[3])? != number(row.fields[3])?
                || (name != "root"
                    && (existing.fields[5] != row.fields[5]
                        || existing.fields[6] != row.fields[6]
                        || ((locked(row.fields[1]) || locked(signed_auth.fields[1]))
                            && !locked(existing.fields[1])
                            && !locked(existing_auth.fields[1]))))
            {
                return Err(NativeAccountError::Conflict);
            }
            continue;
        }
        if old
            .passwd
            .iter()
            .any(|r| number(r.fields[2]).ok() == number(row.fields[2]).ok())
            || number(row.fields[2])? == 0
            || number(row.fields[3])? == 0
            || !non_login_shell(row.fields[6])
        {
            return Err(NativeAccountError::Conflict);
        }
        let auth = find(&image.shadow, name).ok_or(NativeAccountError::Invalid)?;
        if !locked(auth.fields[1]) {
            return Err(NativeAccountError::Conflict);
        }
        append_line(&mut passwd, row.line.as_bytes())?;
        append_line(&mut shadow, auth.line.as_bytes())?;
    }
    for row in &image.group {
        if let Some(existing) = find(&old.group, row.fields[0]) {
            if number(existing.fields[2])? != number(row.fields[2])? {
                return Err(NativeAccountError::Conflict);
            }
        } else if old
            .group
            .iter()
            .any(|r| number(r.fields[2]).ok() == number(row.fields[2]).ok())
        {
            return Err(NativeAccountError::Conflict);
        }
    }
    let group = merge_groups(source.group, &old, &image)?;
    let gshadow = if old.gshadow.is_some() || image.gshadow.is_some() {
        Some(merge_gshadow(&old, &image)?)
    } else {
        None
    };
    let merged = MergedAccounts {
        passwd,
        group,
        shadow,
        gshadow,
    };
    // Revalidate the complete cross-file result, including newly added members.
    validate(&AccountFiles {
        passwd: &merged.passwd,
        group: &merged.group,
        shadow: &merged.shadow,
        gshadow: merged.gshadow.as_deref().map(|v| v.as_slice()),
    })?;
    Ok(merged)
}

impl<'a> Tables<'a> {
    fn parse(files: &AccountFiles<'a>) -> Result<Self> {
        let tables = Self {
            passwd: rows(files.passwd)?,
            group: rows(files.group)?,
            shadow: rows(files.shadow)?,
            gshadow: files.gshadow.map(rows).transpose()?,
        };
        let mut uids = BTreeSet::new();
        let mut gids = BTreeSet::new();
        for row in &tables.passwd {
            let fields = &row.fields;
            let uid = number(fields[2])?;
            let gid = number(fields[3])?;
            if !uids.insert(uid)
                || (uid == 0) != (fields[0] == "root")
                || !matches!(fields[1], "x" | "!" | "!!" | "*")
                || !absolute(fields[5])
                || !absolute(fields[6])
                || !tables
                    .group
                    .iter()
                    .any(|r| number(r.fields[2]).ok() == Some(gid))
                || find(&tables.shadow, fields[0]).is_none()
            {
                return Err(NativeAccountError::Invalid);
            }
        }
        let root = find(&tables.passwd, "root").ok_or(NativeAccountError::Invalid)?;
        if root.fields[2] != "0"
            || root.fields[3] != "0"
            || root.fields[5] != "/root"
            || !login_shell(root.fields[6])
        {
            return Err(NativeAccountError::Unsupported);
        }
        for row in &tables.group {
            let gid = number(row.fields[2])?;
            if !gids.insert(gid)
                || (gid == 0) != (row.fields[0] == "root")
                || !matches!(row.fields[1], "" | "x" | "!" | "!!" | "*")
            {
                return Err(NativeAccountError::Invalid);
            }
            check_members(row.fields[3], &tables.passwd)?;
        }
        if find(&tables.group, "root").is_none() {
            return Err(NativeAccountError::Invalid);
        }
        for row in &tables.shadow {
            if find(&tables.passwd, row.fields[0]).is_none()
                || !password_field(row.fields[1], false)
                || row.fields[2..]
                    .iter()
                    .any(|v| !v.is_empty() && v.parse::<u64>().is_err())
            {
                return Err(NativeAccountError::Invalid);
            }
        }
        if let Some(gshadow) = &tables.gshadow {
            if gshadow.len() != tables.group.len() {
                return Err(NativeAccountError::Invalid);
            }
            for row in gshadow {
                let group =
                    find(&tables.group, row.fields[0]).ok_or(NativeAccountError::Invalid)?;
                check_members(row.fields[2], &tables.passwd)?;
                check_members(row.fields[3], &tables.passwd)?;
                if !password_field(row.fields[1], true)
                    || members(row.fields[3])? != members(group.fields[3])?
                {
                    return Err(NativeAccountError::Invalid);
                }
            }
        }
        Ok(tables)
    }
}

fn rows<const N: usize>(bytes: &[u8]) -> Result<Vec<Row<'_, N>>> {
    if bytes.is_empty() || bytes.len() > MAX_TABLE_BYTES {
        return Err(NativeAccountError::Limit);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| NativeAccountError::Invalid)?;
    if text.chars().any(|c| c.is_control() && c != '\n') {
        return Err(NativeAccountError::Invalid);
    }
    let count = text.lines().count();
    if count > MAX_ROWS {
        return Err(NativeAccountError::Limit);
    }
    let mut result = Vec::with_capacity(count);
    let mut names = BTreeSet::new();
    for line in text.lines() {
        if line.len() > MAX_LINE {
            return Err(NativeAccountError::Limit);
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = [""; N];
        let mut parts = line.split(':');
        for field in &mut fields {
            *field = parts.next().ok_or(NativeAccountError::Invalid)?;
        }
        if parts.next().is_some() || !name(fields[0]) || !names.insert(fields[0]) {
            return Err(NativeAccountError::Invalid);
        }
        result.push(Row { line, fields });
    }
    if result.is_empty() {
        return Err(NativeAccountError::Invalid);
    }
    Ok(result)
}

fn find<'a, 'b, const N: usize>(rows: &'b [Row<'a, N>], name: &str) -> Option<&'b Row<'a, N>> {
    rows.iter().find(|row| row.fields[0] == name)
}
fn number(value: &str) -> Result<u32> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(NativeAccountError::Invalid);
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|v| *v != u32::MAX)
        .ok_or(NativeAccountError::Invalid)
}
fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && (value.as_bytes()[0].is_ascii_alphabetic() || value.as_bytes()[0] == b'_')
        && value.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_alphanumeric()
                || b == b'_'
                || (i > 0 && matches!(b, b'-' | b'.'))
                || (b == b'$' && i == value.len() - 1 && i > 0)
        })
}
fn absolute(value: &str) -> bool {
    value == "/"
        || (value.starts_with('/')
            && !value.ends_with('/')
            && value[1..]
                .split('/')
                .all(|p| !p.is_empty() && p != "." && p != "..")
            && !value.chars().any(char::is_whitespace))
}
/// Where the images' own accounts end and accounts made on a device begin. The
/// top of the range leaves `nobody` to the image.
fn person_id(id: u32) -> bool {
    (1000..60000).contains(&id)
}

/// Whose SSH state a raw update would lose: not root's, which is carried, and not
/// that of an account the image owns.
pub(super) fn person(uid: &str, shell: &str) -> bool {
    number(uid).is_ok_and(|uid| uid != 0 && (person_id(uid) || login_shell(shell)))
}

pub(super) fn login_shell(value: &str) -> bool {
    matches!(
        value,
        "/bin/sh" | "/bin/ash" | "/bin/bash" | "/usr/bin/bash"
    )
}
fn non_login_shell(value: &str) -> bool {
    matches!(value, "/bin/false" | "/sbin/nologin" | "/usr/sbin/nologin")
}
fn locked(value: &str) -> bool {
    value.starts_with('!') || value.starts_with('*')
}
fn password_field(value: &str, allow_empty: bool) -> bool {
    if value.is_empty() {
        return allow_empty;
    }
    value.len() <= 1024
        && !value.chars().any(char::is_control)
        && (locked(value) || native_hash::matches_musl_1_2_6(value))
}
fn members(value: &str) -> Result<BTreeSet<&str>> {
    let mut result = BTreeSet::new();
    if !value.is_empty() {
        for member in value.split(',') {
            if !name(member) || !result.insert(member) {
                return Err(NativeAccountError::Invalid);
            }
        }
    }
    Ok(result)
}
fn check_members(value: &str, users: &[Row<'_, 7>]) -> Result<()> {
    for member in members(value)? {
        if find(users, member).is_none() {
            return Err(NativeAccountError::Invalid);
        }
    }
    Ok(())
}

fn bounded_copy(value: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(MAX_TABLE_BYTES));
    push(&mut out, value)?;
    Ok(out)
}
fn push(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    if value.len() > MAX_TABLE_BYTES - out.len() {
        return Err(NativeAccountError::Limit);
    }
    out.extend_from_slice(value);
    Ok(())
}
fn append_line(out: &mut Vec<u8>, line: &[u8]) -> Result<()> {
    if !out.is_empty() && out.last() != Some(&b'\n') {
        push(out, b"\n")?;
    }
    push(out, line)?;
    push(out, b"\n")
}
fn union<'a>(old: &'a str, new: &'a str) -> Result<Vec<&'a str>> {
    let mut result = Vec::with_capacity(members(old)?.len() + members(new)?.len());
    for value in [old, new] {
        if !value.is_empty() {
            for member in value.split(',') {
                if !result.contains(&member) {
                    result.push(member);
                }
            }
        }
    }
    Ok(result)
}
fn write_fields(out: &mut Vec<u8>, prefix: &[&str], members: &[&str]) -> Result<()> {
    for field in prefix {
        push(out, field.as_bytes())?;
        push(out, b":")?;
    }
    for (i, member) in members.iter().enumerate() {
        if i != 0 {
            push(out, b",")?;
        }
        push(out, member.as_bytes())?;
    }
    push(out, b"\n")
}
fn merge_groups(source: &[u8], old: &Tables<'_>, image: &Tables<'_>) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(MAX_TABLE_BYTES));
    let text = std::str::from_utf8(source).map_err(|_| NativeAccountError::Invalid)?;
    for chunk in text.split_inclusive('\n') {
        let line = chunk.strip_suffix('\n').unwrap_or(chunk);
        let Some(row) = old.group.iter().find(|row| row.line == line) else {
            push(&mut out, chunk.as_bytes())?;
            continue;
        };
        let new = find(&image.group, row.fields[0])
            .map(|r| r.fields[3])
            .unwrap_or("");
        let combined = union(row.fields[3], new)?;
        if combined.len() == members(row.fields[3])?.len() {
            push(&mut out, chunk.as_bytes())?;
        } else {
            write_fields(&mut out, &row.fields[..3], &combined)?;
        }
    }
    for row in &image.group {
        if find(&old.group, row.fields[0]).is_none() {
            append_line(&mut out, row.line.as_bytes())?;
        }
    }
    Ok(out)
}
fn merge_gshadow(old: &Tables<'_>, image: &Tables<'_>) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(MAX_TABLE_BYTES));
    for group in old.group.iter().chain(
        image
            .group
            .iter()
            .filter(|g| find(&old.group, g.fields[0]).is_none()),
    ) {
        let name = group.fields[0];
        let existing = old.gshadow.as_deref().and_then(|r| find(r, name));
        let signed = image.gshadow.as_deref().and_then(|r| find(r, name));
        let (password, admins) = if let Some(existing) = existing {
            if let Some(signed) = signed
                && !members(signed.fields[2])?.is_subset(&members(existing.fields[2])?)
            {
                return Err(NativeAccountError::Conflict);
            }
            (existing.fields[1], existing.fields[2])
        } else if find(&old.group, name).is_none() {
            signed
                .map(|r| (r.fields[1], r.fields[2]))
                .unwrap_or(("!", ""))
        } else {
            if signed.is_some_and(|r| !r.fields[2].is_empty()) {
                return Err(NativeAccountError::Conflict);
            }
            // Preserve old inline group password semantics when introducing
            // gshadow; an unresolved x marker is already a locked password.
            (
                if group.fields[1] == "x" {
                    "!"
                } else {
                    group.fields[1]
                },
                "",
            )
        };
        let old_members = find(&old.group, name).map(|r| r.fields[3]).unwrap_or("");
        let new_members = find(&image.group, name).map(|r| r.fields[3]).unwrap_or("");
        write_fields(
            &mut out,
            &[name, password, admins],
            &union(old_members, new_members)?,
        )?;
    }
    Ok(out)
}

#[cfg(test)]
#[path = "restore_native_tests.rs"]
mod tests;
