//! Syntax/parameter compatibility with the pinned image's musl 1.2.6 crypt.
//! No password is accepted, guessed, hashed or rehashed here. Locked shadow
//! markers are handled separately, without unlocking their opaque suffix.

use base64::Engine as _;
use zeroize::Zeroizing;

const CRYPT64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

pub(super) fn matches_musl_1_2_6(value: &str) -> bool {
    if value.chars().any(char::is_control) {
        return false;
    }
    if value.starts_with("$2") && value.as_bytes().get(3) == Some(&b'$') {
        return bcrypt(value);
    }
    if value.starts_with("$1$") || value.starts_with("$5$") || value.starts_with("$6$") {
        return modular(value);
    }
    if value.starts_with('_') {
        return value.len() == 20
            && value.as_bytes()[1..].iter().all(|b| CRYPT64.contains(b))
            && &value.as_bytes()[1..5] != b"...."
            && canonical_des_tail(value);
    }
    // Old DES preserves its two literal salt bytes, including non-crypt64
    // punctuation. Remaining bytes are the canonical encoded digest.
    value.len() == 13
        && value.as_bytes()[..2]
            .iter()
            .all(|b| !matches!(b, 0 | b'\n' | b':'))
        && value.as_bytes()[2..].iter().all(|b| CRYPT64.contains(b))
        && canonical_des_tail(value)
}

fn canonical_des_tail(value: &str) -> bool {
    value.as_bytes().last().is_some_and(|last| {
        CRYPT64
            .iter()
            .position(|b| b == last)
            .is_some_and(|index| index % 4 == 0)
    })
}

fn modular(value: &str) -> bool {
    let mut fields = value.split('$');
    if fields.next() != Some("") {
        return false;
    }
    let (salt_max, digest_len, last_max, sha) = match fields.next() {
        Some("1") => (8, 22, 3, false),
        Some("5") => (16, 43, 15, true),
        Some("6") => (16, 86, 3, true),
        _ => return false,
    };
    let Some(mut salt) = fields.next() else {
        return false;
    };
    if sha && salt.starts_with("rounds=") {
        let rounds = &salt[7..];
        // musl canonicalizes leading zeros and clamps low counts, so such
        // stored encodings cannot compare equal to its crypt() output.
        if rounds.starts_with('0')
            || !rounds.bytes().all(|b| b.is_ascii_digit())
            || !rounds
                .parse::<u32>()
                .is_ok_and(|n| (1000..=9_999_999).contains(&n))
        {
            return false;
        }
        let Some(next) = fields.next() else {
            return false;
        };
        salt = next;
    }
    let Some(digest) = fields.next() else {
        return false;
    };
    salt.len() <= salt_max
        && !salt.contains(':')
        && !salt.chars().any(char::is_control)
        && digest.len() == digest_len
        && digest.bytes().all(|b| CRYPT64.contains(&b))
        && digest.as_bytes().last().is_some_and(|last| {
            CRYPT64
                .iter()
                .position(|b| b == last)
                .is_some_and(|n| n <= last_max)
        })
        && fields.next().is_none()
}

fn bcrypt(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 60
        || bytes[0..2] != *b"$2"
        || !matches!(bytes[2], b'a' | b'b' | b'x' | b'y')
        || bytes[3] != b'$'
        || bytes[6] != b'$'
        || !bytes[4..6].iter().all(|b| b.is_ascii_digit())
    {
        return false;
    }
    let cost = (bytes[4] - b'0') * 10 + bytes[5] - b'0';
    // The pinned musl BF_crypt only accepts two-digit counts through 19 and
    // requires a minimum work factor of 16 (cost 4).
    if !(4..=19).contains(&cost) {
        return false;
    }
    let mut salt = Zeroizing::new([0; 16]);
    let mut digest = Zeroizing::new([0; 23]);
    bcrypt::BASE_64
        .decode_slice(&bytes[7..29], &mut *salt)
        .is_ok_and(|n| n == 16)
        && bcrypt::BASE_64
            .decode_slice(&bytes[29..], &mut *digest)
            .is_ok_and(|n| n == 23)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_hash_formats_and_pinned_cost_limits_are_checked_without_hashing() {
        for (method, length) in [("1", 22), ("5", 43), ("6", 86)] {
            assert!(matches_musl_1_2_6(&format!(
                "${method}$salt${}",
                ".".repeat(length)
            )));
        }
        let sample = bcrypt::hash("synthetic fixture only", 4).unwrap();
        for variant in ["2a", "2b", "2x", "2y"] {
            let value = sample.replacen("2b", variant, 1);
            assert!(matches_musl_1_2_6(&value));
            assert!(matches_musl_1_2_6(&value.replacen("$04$", "$19$", 1)));
            assert!(!matches_musl_1_2_6(&value.replacen("$04$", "$20$", 1)));
        }
        for index in [28, 59] {
            let mut noncanonical = sample.as_bytes().to_vec();
            noncanonical[index] = b'/';
            assert!(!matches_musl_1_2_6(
                std::str::from_utf8(&noncanonical).unwrap()
            ));
        }
        assert!(matches_musl_1_2_6("abJnggxhB/yWI"));
        assert!(matches_musl_1_2_6(&format!("_J9..CCCC{}", ".".repeat(11))));
        assert!(matches_musl_1_2_6("_0.../9ZzX7iSJNd21sU"));
        assert!(matches_musl_1_2_6(&format!(
            "$6$rounds=9999999$salt${}",
            ".".repeat(86)
        )));
        assert!(matches_musl_1_2_6(
            "$5$rounds=1234$abc0123456789$3VfDjPt05VHFn47C/ojFZ6KRPYrOjj1lLbH.dkF3bZ6"
        ));
        for (method, salt, length) in [
            ("1", "é+ ,=", 22),
            ("5", "a+b,c =é", 43),
            ("6", "a+b,c =é", 86),
        ] {
            assert!(matches_musl_1_2_6(&format!(
                "${method}${salt}${}",
                ".".repeat(length)
            )));
        }
        assert!(matches_musl_1_2_6(&format!("+ {}", ".".repeat(11))));
        assert!(matches_musl_1_2_6(&format!("$!{}", ".".repeat(11))));
    }

    #[test]
    fn unsupported_ids_bad_parameters_lengths_and_noncanonical_encodings_are_rejected() {
        for value in [
            "$y$j9T$salt$hash",
            "$argon2id$v=19$m=8,t=1,p=1$salt$hash",
            "$7$salt$hash",
            "$5$rounds=01000$salt$...........................................",
            "$5$rounds=999$salt$...........................................",
            "$5$rounds=10000000$salt$...........................................",
            "$5$rounds=1000$salt$..........................................z",
            "$5$salt$short",
            "$5$salt$...........................................$trailing",
            "$1$123456789$......................",
            "_...................",
            "abJnggxhB/yWJ",
            "_0.../9ZzX7iSJNd21sV",
            "invalid plaintext",
        ] {
            assert!(!matches_musl_1_2_6(value));
        }
    }
}
