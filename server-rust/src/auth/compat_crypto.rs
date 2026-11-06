use aes::Aes256;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cbc::Decryptor;
use cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use md5::{Digest, Md5};

use crate::{AppError, Result};

const LEGACY_SECRET_KEY: &[u8] = b"nanokvm-sipeed-2024";
const OPENSSL_SALTED_PREFIX: &[u8] = b"Salted__";
/// The longest password the web client can send: 256 bytes, URI-encoded and
/// then encrypted, stays well below this.
/// Decoding cannot increase the byte count. Keep the wider login bound for
/// legacy credentials; new-password policy is enforced separately.
pub(crate) const MAX_ENCODED_PASSWORD_BYTES: usize = 4096;

pub fn decode_frontend_password(input: &str) -> Result<String> {
    // Refused before any decoding, hashing or lockout bookkeeping.
    if input.len() > MAX_ENCODED_PASSWORD_BYTES {
        return Err(AppError::BadRequest("password is too long".to_string()));
    }
    let decoded = urlencoding::decode(input)
        .map_err(|err| AppError::BadRequest(format!("invalid password encoding: {err}")))?;
    let decoded = decoded.into_owned();

    if decoded.starts_with("U2FsdGVkX1") {
        decrypt_cryptojs_passphrase(&decoded)
    } else {
        Ok(decoded)
    }
}

fn decrypt_cryptojs_passphrase(encoded: &str) -> Result<String> {
    let mut bytes = STANDARD
        .decode(encoded)
        .map_err(|_| AppError::BadRequest("invalid encrypted password".to_string()))?;
    if bytes.len() < 16 || &bytes[..8] != OPENSSL_SALTED_PREFIX {
        return Err(AppError::BadRequest(
            "invalid encrypted password".to_string(),
        ));
    }

    let salt = bytes[8..16].to_vec();
    let ciphertext = &mut bytes[16..];
    let (key, iv) = evp_bytes_to_key(LEGACY_SECRET_KEY, &salt);
    let decryptor = Decryptor::<Aes256>::new_from_slices(&key, &iv)
        .map_err(|_| AppError::BadRequest("invalid encrypted password".to_string()))?;
    let plaintext = decryptor
        .decrypt_padded_mut::<Pkcs7>(ciphertext)
        .map_err(|_| AppError::BadRequest("invalid encrypted password".to_string()))?;
    String::from_utf8(plaintext.to_vec())
        .map_err(|_| AppError::BadRequest("invalid encrypted password".to_string()))
}

fn evp_bytes_to_key(password: &[u8], salt: &[u8]) -> ([u8; 32], [u8; 16]) {
    let mut out = Vec::with_capacity(48);
    let mut previous: Vec<u8> = Vec::new();

    while out.len() < 48 {
        let mut hasher = Md5::new();
        if !previous.is_empty() {
            hasher.update(&previous);
        }
        hasher.update(password);
        hasher.update(salt);
        previous = hasher.finalize().to_vec();
        out.extend_from_slice(&previous);
    }

    let mut key = [0_u8; 32];
    let mut iv = [0_u8; 16];
    key.copy_from_slice(&out[..32]);
    iv.copy_from_slice(&out[32..48]);
    (key, iv)
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
    fn encrypted_legacy_passwords_stay_bounded_and_compatible() {
        use cipher::BlockEncryptMut;
        for length in [300, 1024, 4096] {
            let plaintext = "p".repeat(length);
            let salt = b"testonly";
            let (key, iv) = evp_bytes_to_key(LEGACY_SECRET_KEY, salt);
            let mut buffer = vec![0; length + 16];
            buffer[..length].copy_from_slice(plaintext.as_bytes());
            let ciphertext = cbc::Encryptor::<Aes256>::new_from_slices(&key, &iv)
                .unwrap()
                .encrypt_padded_mut::<Pkcs7>(&mut buffer, length)
                .unwrap();
            let mut envelope = Vec::from(OPENSSL_SALTED_PREFIX);
            envelope.extend_from_slice(salt);
            envelope.extend_from_slice(ciphertext);
            let encoded = STANDARD.encode(envelope);
            if encoded.len() <= MAX_ENCODED_PASSWORD_BYTES {
                assert_eq!(decode_frontend_password(&encoded).unwrap(), plaintext);
            } else {
                assert!(decode_frontend_password(&encoded).is_err());
            }
        }
    }
}
