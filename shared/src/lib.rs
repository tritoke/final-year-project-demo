#![no_std]

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{AeadCore, AeadInPlace, ChaCha20Poly1305, Key, KeyInit};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

// present a CRUD interface to the client
#[derive(Serialize, Deserialize, Debug)]
pub enum Action {
    Create {
        #[serde(with = "serde_byte_array")]
        enc_data: [u8; 128],
        #[serde(with = "serde_byte_array")]
        metadata: [u8; 128],
    },
    Read {
        entry_idx: u32,
    },
    ReadEntryMetadata {
        entry_idx: u32,
    },
    ReadSectorMetadata,
    Update {
        entry_idx: u32,
        #[serde(with = "serde_byte_array")]
        new_enc_data: [u8; 128],
        #[serde(with = "serde_byte_array")]
        new_metadata: [u8; 128],
    },
    Delete {
        entry_idx: u32,
    },
    // delete everything - its my program I make the messages >:)
    TheNsaAreHere,
}

/// used to grant an action - this prevents replay attacks
#[derive(Serialize, Deserialize, Debug)]
pub struct ActionToken(#[serde(with = "serde_byte_array")] [u8; 16]);

impl ActionToken {
    pub fn random(csprng: &mut impl CryptoRngCore) -> Self {
        let mut s = Self([0u8; 16]);
        csprng.fill_bytes(&mut s.0);
        s
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    Success,
    NewEntry {
        index: u32,
    },
    SectorMetadata {
        #[serde(with = "serde_byte_array")]
        populated: [u8; 64],
    },
    EntryMetadata {
        #[serde(with = "serde_byte_array")]
        metadata: [u8; 128],
    },
    Entry {
        #[serde(with = "serde_byte_array")]
        data: [u8; 128],
        #[serde(with = "serde_byte_array")]
        metadata: [u8; 128],
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    Token(ActionToken),
    ActionRequest { action: Action, token: ActionToken },
    ActionResponse { response: Response },
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedMessage<'data> {
    pub enc_data: &'data [u8],
    #[serde(with = "serde_byte_array")]
    pub nonce: [u8; 12],
    #[serde(with = "serde_byte_array")]
    pub tag: [u8; 16],
}

impl<'data> EncryptedMessage<'data> {
    pub fn encrypt(
        data: &'data mut [u8],
        key: &Key,
        csprng: &mut impl CryptoRngCore,
    ) -> Result<Self, chacha20poly1305::Error> {
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = ChaCha20Poly1305::generate_nonce(csprng);
        let tag = cipher.encrypt_in_place_detached(&nonce, b"", data)?;
        Ok(Self {
            enc_data: data,
            nonce: nonce
                .as_slice()
                .try_into()
                .expect("length invariant broken"),
            tag: tag.as_slice().try_into().expect("length invariant broken"),
        })
    }

    // panics if buf.len() < self.enc_data.len()
    pub fn decrypt_into<'a>(
        &self,
        key: &Key,
        out_buf: &'a mut [u8],
    ) -> Result<&'a mut [u8], chacha20poly1305::Error> {
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = GenericArray::from_slice(&self.nonce).clone();
        let tag = GenericArray::from_slice(&self.tag).clone();
        if out_buf.len() < self.enc_data.len() {
            panic!("insufficient space to decrypt into buf");
        }
        let out = &mut out_buf[..self.enc_data.len()];
        out.copy_from_slice(self.enc_data);
        cipher.decrypt_in_place_detached(&nonce, b"", out, &tag)?;
        Ok(out)
    }
}
