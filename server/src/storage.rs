use core::mem;
use embassy_stm32::flash;
use embassy_stm32::flash::{Error as FlashError, Flash, MAX_ERASE_SIZE};
use embassy_stm32::pac::FLASH_SIZE;

const PASSWORD_SIZE: usize = 40;
const USERNAME_SIZE: usize = 60;
const METADATA_SIZE: usize = 100;

const NONCE_SIZE: usize = 12;
const POLY1305_HASH_SIZE: usize = 16;
const ENCRYPTION_OVERHEAD: usize = NONCE_SIZE + POLY1305_HASH_SIZE;

pub type StorageResult<T> = Result<T, StorageError>;

// use one sector for passwords, to allow copying between sectors when flash needs to be erased
pub const MAX_NO_PASSWORDS: u32 = MAX_ERASE_SIZE as u32 / mem::size_of::<Entry>() as u32;

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

/// Struct for holding the metadata of what is stored and deleted
/// does not enforce invariants, this is the responsbility of the user
struct SectorMetadata {
    populated: [u32; 16],
    deleted: [u32; 16],
}

impl SectorMetadata {
    fn new() -> Self {
        Self {
            populated: [0; 16],
            deleted: [0; 16],
        }
    }

    fn from_flash(flash: &mut Flash<'_>, last_sector: bool) -> Self {
        todo!()
    }

    fn populate_cell(&mut self, mut cell: u16) {
        if cell >= 512 {
            return;
        }

        for i in 0..16 {
            if cell <= 31 {
                self.populated[i] |= 1 << cell;
                break;
            }

            cell -= 32;
        }
    }

    fn is_cell_populated(&self, mut cell: u16) -> bool {
        if cell >= 512 {
            return false;
        }

        for i in 0..16 {
            if cell < 32 {
                return (self.populated[i] >> cell) & 1 == 1;
            }
        }

        false
    }

    fn delete_cell(&mut self, mut cell: u16) {
        if cell >= 512 {
            return;
        }

        for i in 0..16 {
            if cell < 32 {
                self.populated[i] &= !(1 << cell);
                self.deleted[i] |= 1 << cell;
                break;
            }

            cell -= 32;
        }
    }

    fn next_unpopulated_cell(&self) -> Option<u32> {
        for i in 0..16 {
            let taken_cells = self.deleted[i] | self.populated[i];
            if taken_cells != 0xFFFF_FFFF {
                let first_free = taken_cells.trailing_ones();
                return Some(i as u32 * 32 + first_free);
            }
        }

        None
    }
}

/// The struct which is serialised when being stored in flash
/// Sector one refers to the last sector in the flash: 393216..=524288
/// Sector two refers to the one before that: 262144..=393216
pub struct Storage<'flash> {
    metadata: SectorMetadata,
    pub flash: Flash<'flash>,
}

impl<'flash> Storage<'flash> {
    pub fn new(mut flash: Flash<'flash>) -> StorageResult<Self> {
        let mut buf = [0u8; 4];
        flash.blocking_read(FLASH_SIZE as u32 - 4, &mut buf)?;

        // TODO: actually populate the metadata

        let mut storage = Self {
            metadata: SectorMetadata::new(),
            flash,
        };

        Ok(storage)
    }

    fn is_sector_one_active(&mut self) -> StorageResult<bool> {
        // read the first 256 byte of both sectors
        const SECTOR_ONE_START: u32 = (FLASH_SIZE - MAX_ERASE_SIZE) as u32;
        const SECTOR_TWO_START: u32 = (FLASH_SIZE - 2 * MAX_ERASE_SIZE) as u32;

        let mut buf = [0u8; 256];
        self.flash.blocking_read(SECTOR_ONE_START, &mut buf)?;
        let sector_one_erased = buf.iter().all(|x| *x == 0xFF);

        self.flash.blocking_read(SECTOR_TWO_START, &mut buf)?;
        let sector_two_erased = buf.iter().all(|x| *x == 0xFF);

        // sector two is only active if sector one is erased and sector two isn't
        // the case when neither are erased is erroneous so just take sector 1 as active
        let sector_one_active = !(sector_one_erased & !sector_two_erased);

        Ok(sector_one_active)
    }

    const fn entry_to_offset(entry: u32) -> u32 {
        FLASH_SIZE as u32 - 4 - (entry + 1) * mem::size_of::<Entry>() as u32
    }

    // pub fn add_entry(&mut self, entry: Entry) -> Result<(), StorageError> {
    //     // check we have space
    //     if self.no_entries >= MAX_NO_PASSWORDS {
    //         return Err(StorageError::MaxPasswordsStored);
    //     }

    //     // calculate the offset then store to flash, incrementing after a successful store
    //     let offset = Self::entry_to_offset(self.no_entries);
    //     defmt::debug!("offset = {}", offset);
    //     let bytes = entry.serialize();
    //     defmt::debug!("bytes = {:x}", bytes);
    //     self.flash.blocking_write(offset, &bytes)?;
    //     self.update_no_entries(self.no_entries + 1)?;

    //     Ok(())
    // }

    // pub fn get_entry(&mut self, entry_idx: u32) -> Result<Entry, StorageError> {
    //     // check the entry is in bounds
    //     if entry_idx >= self.no_entries {
    //         return Err(StorageError::NonExistentEntry);
    //     }

    //     // calculate the offset then store to flash, incrementing after a successful store
    //     let offset = Self::entry_to_offset(entry_idx);
    //     defmt::debug!("offset = {}", offset);
    //     let mut buffer = [0u8; 256];
    //     self.flash.blocking_read(offset, &mut buffer)?;
    //     defmt::debug!("buffer = {:x}", buffer);

    //     Ok(Entry::deserialize(buffer))
    // }

    // pub fn del_entry(&mut self, entry_idx: u32) -> Result<(), StorageError> {
    //     // check the entry is in bounds
    //     if entry_idx >= self.no_entries {
    //         return Err(StorageError::NonExistentEntry);
    //     }

    //     // to perform a deletion we swap the entry to be deleted with the last one
    //     // if it is the last one then write data over the top
    //     if entry_idx == self.no_entries - 1 {
    //         // to overwrite the last entry:
    //         // 1. decrement the number of entries
    //         // 2. add another dummy entry to overwrite the old data
    //         // 3. decrement the number of entries again to leave
    //         self.no_entries -= 1;
    //         self.add_entry(Entry::deserialize([b'A'; 256]))?;
    //     } else {
    //         let last_entry = self.get_entry(self.no_entries - 1)?;

    //         // now overwrite with the last entry
    //         let offset = Self::entry_to_offset(entry_idx);
    //         self.flash.blocking_write(offset, &last_entry.serialize())?;
    //     }

    //     // after all operations were successful decrement the number of entries
    //     self.update_no_entries(self.no_entries - 1)?;

    //     Ok(())
    // }

    // fn update_no_entries(&mut self, no_entries: u32) -> Result<(), StorageError> {
    //     let buf = no_entries.to_be_bytes();
    //     self.flash.blocking_write(FLASH_SIZE as u32 - 4, &buf)?;
    //     self.no_entries = no_entries;
    //     Ok(())
    // }
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

#[cfg(test)]
#[defmt_test::tests]
pub mod tests {
    use crate::storage::{Entry, SectorMetadata};
    use defmt::{assert_eq, debug, warn};

    #[test]
    fn test_entry_serialize() {
        let entry = Entry {
            pwd_data: [0x69; 128],
            metadata: [0x42; 128],
        };

        let ser = entry.serialize();
        let mut correct = [0x69u8; 256];
        correct[128..].fill(0x42);

        assert_eq!(ser, correct);
    }

    #[test]
    fn test_entry_deserialize() {
        let mut ser = [0xABu8; 256];
        ser[128..].fill(0xCD);

        let deser = Entry::deserialize(ser);
        let correct = Entry {
            pwd_data: [0xAB; 128],
            metadata: [0xCD; 128],
        };

        assert_eq!(deser.pwd_data, correct.pwd_data);
        assert_eq!(deser.metadata, correct.metadata);
    }

    #[test]
    fn test_entry_roundtrip_serialization() {
        let entry = Entry {
            pwd_data: [0x69; 128],
            metadata: [0x42; 128],
        };

        let ser = entry.serialize();
        let deser = Entry::deserialize(ser);

        assert_eq!(entry.pwd_data, deser.pwd_data);
        assert_eq!(entry.metadata, deser.metadata);
    }

    #[test]
    fn test_metadata_populate() {
        let mut metadata = SectorMetadata::new();
        metadata.populate_cell(0);
        metadata.populate_cell(4);
        metadata.populate_cell(31);
        metadata.populate_cell(32);
        metadata.populate_cell(59);
        metadata.populate_cell(63);

        let mut correct = [0u32; 16];
        correct[0] = 0x8000_0011;
        correct[1] = 0x8800_0001;

        assert_eq!(metadata.populated, correct);
    }

    #[test]
    fn test_metadata_delete() {
        let mut metadata = SectorMetadata::new();
        metadata.delete_cell(0);
        metadata.delete_cell(4);
        metadata.delete_cell(31);
        metadata.delete_cell(32);
        metadata.delete_cell(59);
        metadata.delete_cell(63);

        let mut correct = [0u32; 16];
        correct[0] = 0x8000_0011;
        correct[1] = 0x8800_0001;

        assert_eq!(metadata.deleted, correct);
    }

    #[test]
    fn test_metadata_populate_then_delete() {
        let mut metadata = SectorMetadata::new();
        metadata.populate_cell(0);
        metadata.populate_cell(4);
        metadata.populate_cell(31);
        metadata.populate_cell(32);
        metadata.populate_cell(59);
        metadata.populate_cell(63);
        metadata.delete_cell(0);
        metadata.delete_cell(63);

        let mut correct = [0u32; 16];
        correct[0] = 0x8000_0010;
        correct[1] = 0x0800_0001;

        assert_eq!(metadata.populated, correct);
    }

    #[test]
    fn test_metadata_next_unpopulated() {
        let mut metadata = SectorMetadata::new();
        for x in 0..50 {
            metadata.populate_cell(x);
        }

        metadata.delete_cell(12);
        metadata.delete_cell(45);
        metadata.delete_cell(51);

        assert_eq!(metadata.next_unpopulated_cell(), Some(50));
    }

    #[test]
    fn test_metadata_next_unpopulated_when_full() {
        let mut metadata = SectorMetadata::new();
        for x in 0..512 {
            metadata.populate_cell(x);
        }
        assert_eq!(metadata.next_unpopulated_cell(), None);

        metadata.delete_cell(1);
        assert_eq!(metadata.next_unpopulated_cell(), None);
    }
}
