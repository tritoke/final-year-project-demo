use core::mem;
use embassy_stm32::flash;
use embassy_stm32::flash::{Error as FlashError, Flash};
use embassy_stm32::pac::FLASH_SIZE;

const PASSWORD_SIZE: usize = 40;
const USERNAME_SIZE: usize = 60;
const METADATA_SIZE: usize = 100;

const NONCE_SIZE: usize = 12;
const POLY1305_HASH_SIZE: usize = 16;
const ENCRYPTION_OVERHEAD: usize = NONCE_SIZE + POLY1305_HASH_SIZE;

// allocate 300kib for passwords
pub const MAX_NO_PASSWORDS: u32 = 300 * 1024 / mem::size_of::<Entry>() as u32;

/// The actual data of each entry (encrypted)
#[repr(packed)]
#[derive(Copy, Clone, defmt::Format)]
pub struct Entry {
    pub pwd_data: [u8; PASSWORD_SIZE + USERNAME_SIZE + ENCRYPTION_OVERHEAD],
    pub metadata: [u8; METADATA_SIZE + ENCRYPTION_OVERHEAD],
}

impl Entry {
    pub fn serialize(self) -> [u8; 256] {
        // SAFETY: Self and the returned array are the same size
        //         mem::transmute guarantees size and alignment are equal
        //         the struct is repr(packed) meaning there will be no padding data between members
        unsafe { mem::transmute(self) }
    }

    pub fn deserialize(data: [u8; 256]) -> Self {
        // SAFETY: Self and the input array are the same size
        //         mem::transmute guarantees size and alignment are equal
        //         the struct is repr(packed) meaning there will be no padding data between members
        unsafe { mem::transmute(data) }
    }
}

/// The struct which is serialised when being stored in flash
pub struct Storage<'a> {
    no_entries: u32,
    flash: Flash<'a>,
}

impl<'flash> Storage<'flash> {
    pub fn new(mut flash: Flash<'flash>) -> Result<Self, StorageError> {
        let mut buf = [0u8; 4];
        flash
            .blocking_read(FLASH_SIZE as u32 - 4, &mut buf)
            .map_err(StorageError::FlashError)?;
        let mut no_entries = u32::from_be_bytes(buf);
        if no_entries > MAX_NO_PASSWORDS {
            no_entries = 0;
        }

        Ok(Self { no_entries, flash })
    }

    pub fn no_entries(&self) -> u32 {
        self.no_entries
    }

    const fn entry_to_offset(entry: u32) -> u32 {
        FLASH_SIZE as u32 - 4 - (entry + 1) * mem::size_of::<Entry>() as u32
    }

    pub fn add_entry(&mut self, entry: Entry) -> Result<(), StorageError> {
        // check we have space
        if self.no_entries >= MAX_NO_PASSWORDS {
            return Err(StorageError::MaxPasswordsStored);
        }

        // calculate the offset then store to flash, incrementing after a successful store
        let offset = Self::entry_to_offset(self.no_entries);
        let bytes = entry.serialize();
        self.flash.blocking_write(offset, &bytes)?;
        self.no_entries += 1;

        Ok(())
    }

    pub fn get_entry(&mut self, entry_idx: u32) -> Result<Entry, StorageError> {
        // check the entry is in bounds
        if entry_idx >= self.no_entries {
            return Err(StorageError::NonExistentEntry);
        }

        // calculate the offset then store to flash, incrementing after a successful store
        let offset = Self::entry_to_offset(entry_idx);
        let mut buffer = [0u8; 256];
        self.flash.blocking_read(offset, &mut buffer)?;

        Ok(Entry::deserialize(buffer))
    }

    pub fn del_entry(&mut self, entry_idx: u32) -> Result<(), StorageError> {
        // check the entry is in bounds
        if entry_idx >= self.no_entries {
            return Err(StorageError::NonExistentEntry);
        }

        // to perform a deletion we swap the entry to be deleted with the last one
        // if it is the last one then write data over the top
        if entry_idx == self.no_entries - 1 {
            // to overwrite the last entry:
            // 1. decrement the number of entries
            // 2. add another dummy entry to overwrite the old data
            // 3. decrement the number of entries again to leave
            self.no_entries -= 1;
            self.add_entry(Entry::deserialize([b'A'; 256]))?;
        } else {
            let last_entry = self.get_entry(self.no_entries - 1)?;

            // now overwrite with the last entry
            let offset = Self::entry_to_offset(entry_idx);
            self.flash.blocking_write(offset, &last_entry.serialize())?;
        }

        // after all operations were successful decrement the number of entries
        self.no_entries -= 1;

        Ok(())
    }
}

#[derive(defmt::Format)]
pub enum StorageError {
    FlashError(FlashError),
    MaxPasswordsStored,
    NonExistentEntry,
}

impl From<FlashError> for StorageError {
    fn from(error: FlashError) -> Self {
        Self::FlashError(error)
    }
}
