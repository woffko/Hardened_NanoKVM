//! Bounded private OpenSSH -T output, never login or restore authorization.

use sha2::{Digest, Sha256};
use std::{io::Read, net::IpAddr};
use zeroize::Zeroizing;

pub const MAX_OUTPUT: usize = 64 * 1024;
const FIELDS: [&[u8]; 10] = [
    b"permitrootlogin",
    b"passwordauthentication",
    b"pubkeyauthentication",
    b"kbdinteractiveauthentication",
    b"permitemptypasswords",
    b"authenticationmethods",
    b"maxauthtries",
    b"logingracetime",
    b"maxsessions",
    b"maxstartups",
];

#[derive(Debug, thiserror::Error)]
#[error("invalid or over-budget private SSH effective-policy input")]
pub struct EffectiveError;

// No Debug/serde: connection addresses are private diagnostic context.
pub struct RootContext {
    argument: String,
}
impl RootContext {
    pub fn new(
        host: &str,
        peer: IpAddr,
        local: IpAddr,
        port: u16,
        rdomain: Option<&str>,
    ) -> Result<Self, EffectiveError> {
        if host.is_empty()
            || host.len() > 253
            || port == 0
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
            || rdomain.is_some_and(|r| {
                r.len() > 32
                    || !r
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
        {
            return Err(EffectiveError);
        }
        let mut argument = format!("user=root,host={host},addr={peer},laddr={local},lport={port}");
        if let Some(rdomain) = rdomain {
            argument.push_str(",rdomain=");
            argument.push_str(rdomain);
        }
        Ok(Self { argument })
    }
    /// Only our fixed order/root profile, not arbitrary OpenSSH -C switches.
    pub fn parse(argument: &str) -> Result<Self, EffectiveError> {
        if argument.len() > 512 {
            return Err(EffectiveError);
        }
        let fields: Vec<_> = argument.split(',').take(7).collect();
        if !matches!(fields.len(), 5 | 6) || fields[0] != "user=root" {
            return Err(EffectiveError);
        }
        let host = fields[1].strip_prefix("host=").ok_or(EffectiveError)?;
        let peer = fields[2]
            .strip_prefix("addr=")
            .ok_or(EffectiveError)?
            .parse()
            .map_err(|_| EffectiveError)?;
        let local = fields[3]
            .strip_prefix("laddr=")
            .ok_or(EffectiveError)?
            .parse()
            .map_err(|_| EffectiveError)?;
        let port = fields[4]
            .strip_prefix("lport=")
            .ok_or(EffectiveError)?
            .parse()
            .map_err(|_| EffectiveError)?;
        let rdomain = fields
            .get(5)
            .map(|v| v.strip_prefix("rdomain=").ok_or(EffectiveError))
            .transpose()?;
        Self::new(host, peer, local, port, rdomain)
    }
    pub fn as_argument(&self) -> &str {
        &self.argument
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootLogin {
    Yes,
    No,
    ProhibitPassword,
    ForcedCommandsOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootPolicySummary {
    pub root_login: RootLogin,
    pub password_authentication: bool,
    pub public_key_authentication: bool,
    pub keyboard_interactive_authentication: bool,
    pub permit_empty_passwords: bool,
    pub max_auth_tries: u32,
    pub login_grace_seconds: u32,
    pub max_sessions: u32,
    pub max_startups: [u32; 3],
}
// No Debug/raw dump/serialization: unknown native string values may be secrets.
pub struct RootEffectivePolicy {
    summary: RootPolicySummary,
    methods: Zeroizing<String>,
    context_and_dump: [u8; 32],
}
impl RootEffectivePolicy {
    pub fn summary(&self) -> RootPolicySummary {
        self.summary
    }
    /// Compare the WHOLE native dump and context, not just the summary. Unknown
    /// arrays/allow-deny/forwarding/env fields remain covered by the digest.
    /// Only comparable for the same exact native runtime, not across versions.
    pub fn same_policy_as(&self, other: &Self) -> bool {
        self.context_and_dump == other.context_and_dump
            && self.methods.as_str() == other.methods.as_str()
    }
}

/// Reads at most64KiB+1, zeroizes all raw output on success/error. The parent
/// must concurrently drain its private pipe, enforce wall time/kill/reap and
/// require native success+EOF. A Cursor/forged dump is NOT native provenance.
pub fn read_policy<R: Read>(
    reader: &mut R,
    context: &RootContext,
) -> Result<RootEffectivePolicy, EffectiveError> {
    let mut raw = Zeroizing::new(Vec::with_capacity(MAX_OUTPUT + 1));
    reader
        .take((MAX_OUTPUT + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|_| EffectiveError)?;
    if raw.is_empty()
        || raw.len() > MAX_OUTPUT
        || raw.last() != Some(&b'\n')
        || raw.contains(&0)
        || raw.contains(&b'\r')
    {
        return Err(EffectiveError);
    }
    let mut values = [None; FIELDS.len()];
    for (count, line) in raw[..raw.len() - 1].split(|b| *b == b'\n').enumerate() {
        if count >= 512 || line.is_empty() {
            return Err(EffectiveError);
        }
        let separator = line.iter().position(|b| *b == b' ').ok_or(EffectiveError)?;
        let (key, tail) = line.split_at(separator);
        if key.is_empty() || !key.iter().all(u8::is_ascii_alphanumeric) {
            return Err(EffectiveError);
        }
        if let Some(index) = FIELDS
            .iter()
            .position(|name| key.eq_ignore_ascii_case(name))
            && values[index].replace(&tail[1..]).is_some()
        {
            return Err(EffectiveError);
        }
    }
    let mut fields = values.into_iter();
    let mut next = || fields.next().flatten().ok_or(EffectiveError);
    let root_login = match next()? {
        b"yes" => RootLogin::Yes,
        b"no" => RootLogin::No,
        b"prohibit-password" | b"without-password" => RootLogin::ProhibitPassword,
        b"forced-commands-only" => RootLogin::ForcedCommandsOnly,
        _ => return Err(EffectiveError),
    };
    let password_authentication = boolean(next()?)?;
    let public_key_authentication = boolean(next()?)?;
    let keyboard_interactive_authentication = boolean(next()?)?;
    let permit_empty_passwords = boolean(next()?)?;
    let methods = methods(next()?)?;
    let max_auth_tries = decimal(next()?)?;
    let login_grace_seconds = decimal(next()?)?;
    let max_sessions = decimal(next()?)?;
    let mut start = next()?.split(|b| *b == b':');
    let max_startups = [
        decimal(start.next().ok_or(EffectiveError)?)?,
        decimal(start.next().ok_or(EffectiveError)?)?,
        decimal(start.next().ok_or(EffectiveError)?)?,
    ];
    if start.next().is_some() || max_startups[1] > 100 || max_startups[0] > max_startups[2] {
        return Err(EffectiveError);
    }
    let mut hash = Sha256::new();
    hash.update(b"nanokvm-sshd-root-effective-v1\0");
    hash.update((context.argument.len() as u64).to_be_bytes());
    hash.update(context.argument.as_bytes());
    hash.update(&raw);
    Ok(RootEffectivePolicy {
        summary: RootPolicySummary {
            root_login,
            password_authentication,
            public_key_authentication,
            keyboard_interactive_authentication,
            permit_empty_passwords,
            max_auth_tries,
            login_grace_seconds,
            max_sessions,
            max_startups,
        },
        methods,
        context_and_dump: hash.finalize().into(),
    })
}

fn boolean(value: &[u8]) -> Result<bool, EffectiveError> {
    match value {
        b"yes" => Ok(true),
        b"no" => Ok(false),
        _ => Err(EffectiveError),
    }
}
fn decimal(value: &[u8]) -> Result<u32, EffectiveError> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(EffectiveError);
    }
    std::str::from_utf8(value)
        .map_err(|_| EffectiveError)?
        .parse()
        .map_err(|_| EffectiveError)
}
fn methods(value: &[u8]) -> Result<Zeroizing<String>, EffectiveError> {
    if value.is_empty() || value.len() > MAX_OUTPUT {
        return Err(EffectiveError);
    }
    let value = std::str::from_utf8(value).map_err(|_| EffectiveError)?;
    if value != "any" {
        for alternative in value.split(' ') {
            for step in alternative.split(',') {
                // auth2_methods_valid strips any suffix before matching a
                // known base. Preserve suffixes opaquely/zeroizing instead of
                // inventing a keyboard-interactive-only syntax restriction.
                let method = step.split_once(':').map_or(step, |(name, _)| name);
                if ![
                    "publickey",
                    "password",
                    "keyboard-interactive",
                    "hostbased",
                    "gssapi-with-mic",
                    "none",
                ]
                .contains(&method)
                {
                    return Err(EffectiveError);
                }
            }
        }
    }
    Ok(Zeroizing::new(value.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    const SPEC: &str = "user=root,host=fixture.example,addr=198.51.100.7,laddr=192.0.2.2,lport=22";
    const DUMP: &[u8] = b"permitrootlogin yes\npasswordauthentication yes\npubkeyauthentication yes\nkbdinteractiveauthentication no\npermitemptypasswords no\nauthenticationmethods any\nmaxauthtries 3\nlogingracetime 120\nmaxsessions 10\nMaxStartups 10:30:100\nhostkey /etc/ssh/first\nhostkey /etc/ssh/second\nSetEnv TOKEN=synthetic-marker\n";
    fn parse(bytes: &[u8]) -> Result<RootEffectivePolicy, EffectiveError> {
        read_policy(
            &mut std::io::Cursor::new(bytes),
            &RootContext::parse(SPEC).unwrap(),
        )
    }
    #[test]
    fn root_context_is_bounded_numeric_and_cannot_inject_other_c_options() {
        assert_eq!(RootContext::parse(SPEC).unwrap().as_argument(), SPEC);
        assert!(RootContext::parse("user=root,host=2001:db8::1,addr=2001:db8::1,laddr=2001:db8::2,lport=2222,rdomain=fixture").is_ok());
        assert!(RootContext::parse(&format!("{SPEC},rdomain=")).is_ok());
        for value in [
            SPEC.replace("root", "admin"),
            format!("{SPEC},version=x"),
            format!("{SPEC},rdomain=a,user=admin"),
            SPEC.replace("host=fixture.example", "host=bad host"),
            SPEC.replace("198.51.100.7", "hostname"),
            SPEC.replace("lport=22", "lport=0"),
            SPEC.replace("lport=22", "lport=65536"),
            SPEC.replace("fixture.example", &"x".repeat(254)),
            SPEC.replace("fixture.example", "bad\nname"),
        ] {
            assert!(RootContext::parse(&value).is_err());
        }
    }
    #[test]
    fn normalized_summary_preserves_root_auth_and_rate_settings_without_forcing_them() {
        let policy = parse(DUMP).unwrap();
        let summary = policy.summary();
        assert_eq!(summary.root_login, RootLogin::Yes);
        assert!(summary.password_authentication && summary.public_key_authentication);
        assert!(!summary.permit_empty_passwords && !summary.keyboard_interactive_authentication);
        assert_eq!(
            (
                summary.max_auth_tries,
                summary.login_grace_seconds,
                summary.max_sessions,
                summary.max_startups
            ),
            (3, 120, 10, [10, 30, 100])
        );
        for (value, expected) in [
            ("no", RootLogin::No),
            ("prohibit-password", RootLogin::ProhibitPassword),
            ("without-password", RootLogin::ProhibitPassword),
            ("forced-commands-only", RootLogin::ForcedCommandsOnly),
        ] {
            let dump = String::from_utf8(DUMP.to_vec()).unwrap().replacen(
                "permitrootlogin yes",
                &format!("permitrootlogin {value}"),
                1,
            );
            assert_eq!(
                parse(dump.as_bytes()).unwrap().summary().root_login,
                expected
            );
        }
    }
    #[test]
    fn whole_dump_and_context_are_bound_including_unknown_repeated_arrays() {
        let first = parse(DUMP).unwrap();
        assert!(first.same_policy_as(&parse(DUMP).unwrap()));
        let changed = String::from_utf8(DUMP.to_vec())
            .unwrap()
            .replace("/etc/ssh/second", "/etc/ssh/third");
        let second = parse(changed.as_bytes()).unwrap();
        assert_eq!(first.summary(), second.summary());
        assert!(!first.same_policy_as(&second));
        let context = RootContext::parse(&SPEC.replace("198.51.100.7", "198.51.100.8")).unwrap();
        assert!(
            !first.same_policy_as(&read_policy(&mut std::io::Cursor::new(DUMP), &context).unwrap())
        );
    }
    #[test]
    fn missing_duplicate_malformed_and_ambiguous_selected_fields_fail_closed() {
        let text = String::from_utf8(DUMP.to_vec()).unwrap();
        for field in FIELDS {
            let name = std::str::from_utf8(field).unwrap();
            let stripped = text
                .lines()
                .filter(|line| !line.split(' ').next().unwrap().eq_ignore_ascii_case(name))
                .map(|s| format!("{s}\n"))
                .collect::<String>();
            assert!(parse(stripped.as_bytes()).is_err());
        }
        for dump in [
            format!("{text}PermitRootLogin no\n"),
            text.replace("passwordauthentication yes", "passwordauthentication 1"),
            text.replace("maxauthtries 3", "maxauthtries -1"),
            text.replace("maxauthtries 3", "maxauthtries 4294967296"),
            text.replace("MaxStartups 10:30:100", "MaxStartups 10:101:100"),
            text.replace("MaxStartups 10:30:100", "MaxStartups 100:30:10"),
            text.replace("MaxStartups 10:30:100", "MaxStartups 10:30:100:1"),
            text.replace(
                "authenticationmethods any",
                "authenticationmethods password,,publickey",
            ),
            text.replace(
                "authenticationmethods any",
                "authenticationmethods synthetic-marker",
            ),
            text.replace("any\n", "any\r\n"),
            format!("{text}bad\0 field\n"),
            format!("{text}\n"),
            text.trim_end().to_owned(),
        ] {
            let error = parse(dump.as_bytes()).err().unwrap();
            assert!(!format!("{error:?} {error}").contains("synthetic-marker"));
        }
        for methods in [
            "publickey,password publickey,keyboard-interactive:pam",
            "publickey,publickey",
            "none",
            "publickey:hostbound,password",
            "keyboard-interactive:",
        ] {
            assert!(
                parse(
                    text.replace(
                        "authenticationmethods any",
                        &format!("authenticationmethods {methods}")
                    )
                    .as_bytes()
                )
                .is_ok()
            );
        }
    }
    #[test]
    fn native_method_chain_lengths_are_not_arbitrarily_restricted() {
        let text = std::str::from_utf8(DUMP).unwrap();
        for value in [
            vec!["publickey"; 20].join(","),
            vec!["publickey:synthetic-suffix"; 20].join(" "),
        ] {
            assert!(
                parse(
                    text.replace(
                        "authenticationmethods any",
                        &format!("authenticationmethods {value}")
                    )
                    .as_bytes()
                )
                .is_ok()
            );
        }
    }
    #[test]
    fn output_and_line_budgets_are_enforced_without_unbounded_read() {
        struct Endless {
            read: usize,
        }
        impl Read for Endless {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                out.fill(b'x');
                self.read += out.len();
                Ok(out.len())
            }
        }
        let mut input = Endless { read: 0 };
        assert!(read_policy(&mut input, &RootContext::parse(SPEC).unwrap()).is_err());
        assert_eq!(input.read, MAX_OUTPUT + 1);
        let mut lines = DUMP.to_vec();
        for _ in 0..512 {
            lines.extend_from_slice(b"hostkey /synthetic\n");
        }
        assert!(parse(&lines).is_err());
    }
}
