use crate::{AppError, Result};

/// The longest password the web client can send. URL decoding cannot increase
/// the byte count. Keep the wider login bound for legacy credentials;
/// new-password policy is enforced separately.
pub(crate) const MAX_ENCODED_PASSWORD_BYTES: usize = 4096;

/// Decode the transport encoding used by the web forms. There is deliberately
/// no static client-side cipher: it gave no confidentiality against anyone who
/// could read the bundle, and passwords are protected by TLS instead.
pub fn decode_frontend_password(input: &str) -> Result<String> {
    // Refused before any decoding, hashing or lockout bookkeeping.
    if input.len() > MAX_ENCODED_PASSWORD_BYTES {
        return Err(AppError::BadRequest("password is too long".to_string()));
    }
    let decoded = urlencoding::decode(input)
        .map_err(|err| AppError::BadRequest(format!("invalid password encoding: {err}")))?;
    Ok(decoded.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_passwords_are_accepted_for_api_clients() {
        assert_eq!(decode_frontend_password("secret").unwrap(), "secret");
    }

    #[test]
    fn url_decoding_is_applied() {
        assert_eq!(decode_frontend_password("a%20b").unwrap(), "a b");
    }

    #[test]
    fn encoded_limit_bounds_plaintext_without_applying_new_password_policy() {
        let legacy = "p".repeat(MAX_ENCODED_PASSWORD_BYTES);
        assert_eq!(decode_frontend_password(&legacy).unwrap(), legacy);
        assert!(decode_frontend_password(&"p".repeat(MAX_ENCODED_PASSWORD_BYTES + 1)).is_err());
        let encoded = "%41".repeat(MAX_ENCODED_PASSWORD_BYTES / 3);
        assert_eq!(
            decode_frontend_password(&encoded).unwrap().len(),
            encoded.len() / 3
        );
        assert!(decode_frontend_password(&(encoded + "%41")).is_err());
    }

    #[test]
    fn static_encrypted_prefix_is_plain_data_not_decrypted() {
        assert_eq!(
            decode_frontend_password("U2FsdGVkX1%2Bnot-a-ciphertext").unwrap(),
            "U2FsdGVkX1+not-a-ciphertext"
        );
    }
}
