use crate::secret_key::SecretKey;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{AeadCore, AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use password_hash::{PasswordHasher, SaltString};
use rand_core::OsRng;
use scrypt::Scrypt;

pub fn compute_vault_key(password: &[u8], secret_key: SecretKey) -> password_hash::Result<Key> {
    let salt = SaltString::encode_b64(secret_key.as_ref()).expect("Salt length invariant broken.");
    let hash = Scrypt.hash_password(password, &salt)?;
    let hash_bytes = hash.hash.expect("Scrypt failed to generate a hash???");

    Ok(Key::from_slice(hash_bytes.as_bytes()).clone())
}

pub fn decrypt_block(block: [u8; 128], key: &Key) -> chacha20poly1305::aead::Result<[u8; 100]> {
    let cipher = ChaCha20Poly1305::new(key);
    let (data, nonce) = block.split_at(128 - 12);
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(&nonce, data)
        .map(|v| v.as_slice().try_into().expect("length invariant broken"))
}

pub fn encrypt_block(data: [u8; 100], key: &Key) -> chacha20poly1305::aead::Result<[u8; 128]> {
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = ChaCha20Poly1305::generate_nonce(OsRng);
    let mut out = cipher.encrypt(&nonce, data.as_slice())?;
    out.extend_from_slice(nonce.as_slice());
    Ok(out.try_into().expect("length invariant broken"))
}
