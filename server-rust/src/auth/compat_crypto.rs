use aes::Aes256;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cbc::Decryptor;
use cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use md5::{Digest, Md5};

use crate::{AppError, Result};

const LEGACY_SECRET_KEY: &[u8] = b"nanokvm-sipeed-2024";
const OPENSSL_SALTED_PREFIX: &[u8] = b"Salted__";

pub fn decode_frontend_password(input: &str) -> Result<String> {
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
}
