use crate::secret_key::SecretKey;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{AeadCore, AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use core::slice::SlicePattern;
use password_hash::{PasswordHasher, SaltString};
use rand_core::OsRng;
use scrypt::Scrypt;

pub fn compute_vault_key(password: &[u8], secret_key: SecretKey) -> password_hash::Result<Key> {
    let salt = SaltString::encode_b64(secret_key.as_ref()).expect("Salt length invariant broken.");
    let hash = Scrypt.hash_password(password, &salt)?;
    let hash_bytes = hash.hash.expect("Scrypt failed to generate a hash???");

    Ok(Key::from_slice(hash_bytes.as_bytes()).clone())
}

pub fn decrypt_block(block: [u8; 128], key: &Key) -> chacha20poly1305::aead::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key);
    let (nonce, data) = block.split_array_ref::<12>();
    let nonce = Nonce::from(*nonce);
    cipher.decrypt(&nonce, data)
}

pub fn encrypt_block(data: [u8; 100], key: &Key) -> chacha20poly1305::aead::Result<[u8; 128]> {
    let mut out = [0u8; 128];
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = ChaCha20Poly1305::generate_nonce(OsRng);
    cipher.encrypt_in_place(&nonce, b"", &mut out[12..], data)?;
    out[..12].copy_from_slice(nonce.as_slice());
    Ok(out)
}
