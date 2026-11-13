//! Bounded strdelim(keyword) + argv_split(arguments) semantics from OpenSSH.
//! This is only a lexical authority guard, not an sshd_config syntax parser.

use super::SshRestoreError;
use std::ops::Range;
use zeroize::Zeroizing;

const MAX_ARGS: usize = 128;
pub(super) struct Line {
    pub keyword: Zeroizing<Vec<u8>>,
    pub plain_command: bool,
    bytes: Zeroizing<Vec<u8>>,
    ranges: Vec<Range<usize>>,
}
impl Line {
    pub fn len(&self) -> usize {
        self.ranges.len()
    }
    pub fn arg(&self, index: usize) -> Option<&str> {
        self.ranges
            .get(index)
            .and_then(|range| std::str::from_utf8(&self.bytes[range.clone()]).ok())
    }
}
pub(super) fn parse(input: &[u8]) -> Result<Option<Line>, SshRestoreError> {
    if input.len() > 8192 || input.contains(&0) {
        return Err(SshRestoreError::Limit);
    }
    let mut end = input.len();
    while end > 0 && (ws(input[end - 1]) || input[end - 1] == 12) {
        end -= 1;
    }
    let input = &input[..end];
    let mut p = 0;
    while p < end && ws(input[p]) {
        p += 1;
    }
    if p == end || input[p] == b'#' {
        return Ok(None);
    }
    // A leading '=' is accepted by strdelim's empty-keyword retry too.
    if input[p] == b'=' {
        p += 1;
        while p < end && ws(input[p]) {
            p += 1;
        }
    }
    let start = p;
    while p < end && !ws(input[p]) && !matches!(input[p], b'=' | b'"') {
        p += 1;
    }
    if p - start > 64 {
        return Err(SshRestoreError::Limit);
    }
    let mut keyword = Zeroizing::new(Vec::with_capacity(64));
    keyword.extend_from_slice(&input[start..p]);
    if p < end && input[p] == b'"' {
        p += 1;
        let start = p;
        while p < end && input[p] != b'"' {
            p += 1;
        }
        if p == end {
            return Err(SshRestoreError::Invalid);
        }
        if p - start > 64 - keyword.len() {
            return Err(SshRestoreError::Limit);
        }
        keyword.extend_from_slice(&input[start..p]);
        p += 1;
        while p < end && ws(input[p]) {
            p += 1;
        }
    } else if p < end {
        let equals = input[p] == b'=';
        p += 1;
        while p < end && ws(input[p]) {
            p += 1;
        }
        if !equals && p < end && input[p] == b'=' {
            p += 1;
            while p < end && ws(input[p]) {
                p += 1;
            }
        }
    }
    if keyword.is_empty() || keyword.len() > 64 || p == end {
        return Err(SshRestoreError::Invalid);
    }
    let mut line = Line {
        keyword,
        plain_command: input[p..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/,:@%+= \t".contains(b)),
        bytes: Zeroizing::new(Vec::with_capacity(input.len())),
        ranges: Vec::with_capacity(MAX_ARGS),
    };
    while p < end {
        if matches!(input[p], b' ' | b'\t') {
            p += 1;
            continue;
        }
        if input[p] == b'#' {
            break;
        }
        if line.len() == MAX_ARGS {
            return Err(SshRestoreError::Limit);
        }
        let start = line.bytes.len();
        let mut quote = 0;
        while p < end {
            let b = input[p];
            if b == b'\\'
                && input.get(p + 1).is_some_and(|next| {
                    matches!(next, b'\'' | b'"' | b'\\') || (quote == 0 && *next == b' ')
                })
            {
                p += 1;
                line.bytes.push(input[p]);
            } else if quote == 0 && matches!(b, b' ' | b'\t') {
                break;
            } else if quote == 0 && matches!(b, b'\'' | b'"') {
                quote = b;
            } else if quote != 0 && b == quote {
                quote = 0;
            } else {
                line.bytes.push(b);
            }
            p += 1;
        }
        if quote != 0 {
            return Err(SshRestoreError::Invalid);
        }
        line.ranges.push(start..line.bytes.len());
    }
    Ok(Some(line))
}
fn ws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}
