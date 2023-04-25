extern crate alloc;
use alloc::vec::Vec;
use core::mem;

const PASSWORD_SIZE: usize = 40;
const USERNAME_SIZE: usize = 60;
const METADATA_SIZE: usize = 100;

const NONCE_SIZE: usize = 12;
const POLY1305_HASH_SIZE: usize = 16;
const ENCRYPTION_OVERHEAD: usize = NONCE_SIZE + POLY1305_HASH_SIZE;

/// The actual data of each entry (encrypted)
#[repr(packed)]
pub struct Entry {
    pub pwd_data: [u8; PASSWORD_SIZE + USERNAME_SIZE + ENCRYPTION_OVERHEAD],
    pub metadata: [u8; METADATA_SIZE + ENCRYPTION_OVERHEAD],
}

impl Entry {
    pub fn serialize(&self) -> &[u8; 256] {
        unsafe { mem::transmute(self) }
    }

    pub fn deserialize(data: &[u8; 256]) -> Self {
        let mut entry = Entry {
            pwd_data: [0; PASSWORD_SIZE + USERNAME_SIZE + ENCRYPTION_OVERHEAD],
            metadata: [0; METADATA_SIZE + ENCRYPTION_OVERHEAD],
        };

        const N: usize = PASSWORD_SIZE + USERNAME_SIZE + ENCRYPTION_OVERHEAD;
        entry.pwd_data.copy_from_slice(&data[..N]);
        entry.metadata.copy_from_slice(&data[N..]);

        entry
    }
}

/// The struct which is serialised when being stored in flash
pub struct Storage {
    pub entries: Vec<Entry>,
}

impl Storage {
    pub fn write_to_flash(&self) {
        todo!()
    }

    pub fn read_from_flash() -> Self {
        todo!()
    }
}
