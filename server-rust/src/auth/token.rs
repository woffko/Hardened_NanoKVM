use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn random_token(bytes_len: usize) -> String {
    URL_SAFE_NO_PAD.encode(random_bytes(bytes_len))
}
