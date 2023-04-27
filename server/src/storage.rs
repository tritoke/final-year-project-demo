use crate::database::SingleUserDatabase;
use chacha20poly1305::consts::U16;
use chacha20poly1305::{AeadCore, AeadInPlace, ChaCha20Poly1305, KeyInit};
use core::mem;
use embassy_stm32::flash;
use embassy_stm32::flash::{Error as FlashError, Flash, MAX_ERASE_SIZE};
use embassy_stm32::pac::FLASH_SIZE;
use rand_core::CryptoRngCore;
use sha2::digest::generic_array::GenericArray;

const PASSWORD_SIZE: usize = 40;
const USERNAME_SIZE: usize = 60;
const METADATA_SIZE: usize = 100;

const NONCE_SIZE: usize = 12;
const POLY1305_HASH_SIZE: usize = 16;
const ENCRYPTION_OVERHEAD: usize = NONCE_SIZE + POLY1305_HASH_SIZE;

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
#[derive(defmt::Format)]
pub struct SectorMetadata {
    populated: [u32; 16],
    deleted: [u32; 16],
}

pub type StorageResult<T> = Result<T, StorageError>;

impl SectorMetadata {
    // 512 total cells, 1 cell reserved for password database for AuCPace
    const MAX_CELL: u16 = 511;

    fn new() -> Self {
        Self {
            populated: [0; 16],
            deleted: [0; 16],
        }
    }

    /// reset all metadata state
    fn reset(&mut self) {
        self.populated.fill(0);
        self.deleted.fill(0);
        self.set_active_sector(Sector::SectorOne);
    }

    fn active_sector(&self) -> Sector {
        if self.populated[15] >> 31 == 1 {
            Sector::SectorOne
        } else {
            Sector::SectorTwo
        }
    }

    fn set_active_sector(&mut self, sector: Sector) {
        match sector {
            Sector::SectorOne => self.populated[15] |= 1 << 31,
            Sector::SectorTwo => self.populated[15] &= !(1 << 31),
        }
    }

    fn populate_cell(&mut self, mut cell: u16) {
        if cell >= Self::MAX_CELL {
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
        if cell >= Self::MAX_CELL {
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
        if cell >= Self::MAX_CELL {
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
                // if we are in the last chunk and only the last one is free then
                if i == 15 && first_free == 31 {
                    return None;
                }
                return Some(i as u32 * 32 + first_free);
            }
        }

        None
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum Sector {
    SectorOne,
    SectorTwo,
}

impl Sector {
    fn base_offset(&self) -> u32 {
        match self {
            Sector::SectorOne => (FLASH_SIZE - MAX_ERASE_SIZE) as u32,
            Sector::SectorTwo => (FLASH_SIZE - MAX_ERASE_SIZE * 2) as u32,
        }
    }

    fn db_offset(&self) -> u32 {
        match self {
            Sector::SectorOne => (FLASH_SIZE - 256) as u32,
            Sector::SectorTwo => (FLASH_SIZE - MAX_ERASE_SIZE - 256) as u32,
        }
    }
}

/// The struct which is serialised when being stored in flash
/// Sector one refers to the last sector in the flash: 393216..=524288
/// Sector two refers to the one before that: 262144..=393216
pub struct Storage<'flash> {
    pub metadata: SectorMetadata,
    pub flash: Flash<'flash>,
}

impl<'flash> Storage<'flash> {
    const KEY: [u8; 32] = const_random::const_random!([u8; 32]);

    pub fn new(mut flash: Flash<'flash>) -> StorageResult<Self> {
        let mut buf = [0u8; 4];
        flash.blocking_read(FLASH_SIZE as u32 - 4, &mut buf)?;

        let metadata = SectorMetadata::new();
        let mut storage = Self { metadata, flash };
        storage.populate_metadata()?;

        Ok(storage)
    }

    fn populate_metadata(&mut self) -> StorageResult<()> {
        // first determine which sector is active
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
        let sector = if sector_one_erased & !sector_two_erased {
            Sector::SectorTwo
        } else {
            Sector::SectorOne
        };
        self.metadata.set_active_sector(sector);

        let sector_base = sector.base_offset();

        // iterate through the sector until we read an 0xFF chunk
        let mut buf = [0u8; 256];
        for entry in 0..511 {
            self.flash
                .blocking_read(sector_base + 256 * entry, &mut buf)?;

            // we have hit the erased part of the sector, thus we can stop reading
            if buf.iter().all(|x| *x == 0xFF) {
                break;
            } else if buf.iter().all(|x| *x == 0) {
                // all zeros indicates a deletec cell
                self.metadata.delete_cell(entry as u16);
            } else {
                // if its not FFFF.. or 0000.. then it is a populated cell
                self.metadata.populate_cell(entry as u16);
            }
        }

        Ok(())
    }

    pub fn erase_sector(&mut self, sector: Sector) -> StorageResult<()> {
        let base = sector.base_offset();
        self.flash
            .blocking_erase(base, base + MAX_ERASE_SIZE as u32)?;
        Ok(())
    }

    // if there is no stored database then it returns a new - empty database
    pub fn retrieve_database(&mut self) -> StorageResult<SingleUserDatabase> {
        let offset = self.metadata.active_sector().db_offset();

        let mut buf = [0u8; 256];
        self.flash.blocking_read(offset, &mut buf)?;

        let cipher = ChaCha20Poly1305::new_from_slice(&Self::KEY).expect("length invariant broken");
        let (enc_data, tag_and_nonce) = buf.split_at_mut(228);
        let nonce = GenericArray::from_slice(&tag_and_nonce[..12]).clone();
        let tag = GenericArray::from_slice(&tag_and_nonce[12..]).clone();

        if cipher
            .decrypt_in_place_detached(&nonce, b"", &mut enc_data[..228], &tag)
            .is_ok()
        {
            defmt::info!("I am a decrypting wizard");
            let db = SingleUserDatabase::deserialise(
                buf[..228].try_into().expect("length invariant broken"),
            );
            defmt::info!("db.is_some() = {}", db.is_some());
            Ok(db.unwrap_or_default())
        } else {
            defmt::info!("I am not a decrypting wizard");
            Ok(SingleUserDatabase::default())
        }
    }

    pub fn store_database(
        &mut self,
        database: &SingleUserDatabase,
        csprng: &mut impl CryptoRngCore,
    ) -> StorageResult<()> {
        let mut enc_data = database.serialise();
        let cipher = ChaCha20Poly1305::new_from_slice(&Self::KEY).expect("length invariant broken");
        let nonce = ChaCha20Poly1305::generate_nonce(csprng);
        // from inspection of the chacha20poly1305 crate the only errors that can occur here are
        // usize::try_into() -> u64, thus this should never panic, usize on this platform is 32 bits
        let tag = cipher
            .encrypt_in_place_detached(&nonce, b"", &mut enc_data)
            .expect("usize magically grew bigger than u64?");

        // if we are storing a database, any existing passsword data is meaningless
        self.metadata.reset();
        self.erase_sector(Sector::SectorOne)?;
        self.erase_sector(Sector::SectorTwo)?;

        // write the new database, encrypted data, then nonce, then tag
        let offset = self.metadata.active_sector().db_offset();
        self.flash.blocking_write(offset, &enc_data)?;
        self.flash.blocking_write(offset + 228, &nonce)?;
        self.flash.blocking_write(offset + 240, &tag)?;

        Ok(())
    }

    // fn entry_to_offset(&self, entry: u32) -> u32 {
    //     let sector_base = if self.metadata.is_sector_one_active() {
    //         FLASH_SIZE - MAX_ERASE_SIZE
    //     } else {
    //         FLASH_SIZE - 2 * MAX_ERASE_SIZE
    //     } as u32;
    // }

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
    use crate::database::SingleUserDatabase;
    use crate::storage::{Entry, SectorMetadata, StorageResult};
    use aucpace::StrongDatabase;
    use curve25519_dalek::{RistrettoPoint, Scalar};
    use defmt::{assert_eq, debug, info, warn, Debug2Format};
    use password_hash::ParamsString;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

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
        for x in 0..511 {
            metadata.populate_cell(x);
        }
        assert_eq!(metadata.next_unpopulated_cell(), None);

        metadata.delete_cell(1);
        assert_eq!(metadata.next_unpopulated_cell(), None);
    }

    #[test]
    fn test_metadata_set_sector_one_active() {
        let mut metadata = SectorMetadata::new();
        assert!(!metadata.active_sector());
        metadata.set_sector_one_active(true);
        assert!(metadata.active_sector());
        metadata.set_sector_one_active(false);
        assert!(!metadata.active_sector());
    }

    #[test]
    fn test_database_serialise_roundtrip() {
        let mut csprng = ChaCha8Rng::seed_from_u64(0xDEADBEEF_CAFEBABE);
        let mut database = SingleUserDatabase::default();

        let username = b"tritoke";
        let verifier = RistrettoPoint::random(&mut csprng);
        let q = Scalar::random(&mut csprng);
        let mut params = ParamsString::new();
        if let Err(e) = params.add_str("id", "coolcrypt3") {
            debug!("id: e = {}", Debug2Format(&e));
        }
        if let Err(e) = params.add_decimal("e", 69) {
            debug!("e: e = {}", Debug2Format(&e));
        }
        if let Err(e) = params.add_decimal("k", 420) {
            debug!("k: e = {}", Debug2Format(&e));
        }

        database.store_verifier_strong(b"tritoke", None, verifier, q, params.clone());

        let ser = database.serialise();
        let db = defmt::unwrap!(SingleUserDatabase::deserialise(ser));

        let (vv, qq, pp) = defmt::unwrap!(db.lookup_verifier_strong(username));
        assert!(vv == verifier);
        assert!(qq == q);
        assert!(pp == params);
    }
}
