use std::collections::HashMap;
use std::mem;

#[derive(Default, Clone)]
pub struct Metadata {
    populated: bool,
    entries: HashMap<u32, Option<String>>,
}

impl Metadata {
    pub fn new(sector_metadata: [u8; 64]) -> Self {
        // transmuting straight to u32 is unsound due to alignment
        let sector_ints: [[u8; 4]; 16] = unsafe { mem::transmute(sector_metadata) };
        // we can now use array.map to recover our LE ints
        let sector_metadata = sector_ints.map(u32::from_le_bytes);
        let mut entries = HashMap::new();
        for (i, &block) in sector_metadata.iter().enumerate() {
            for x in 0..32 {
                // verifier thingy
                if i == 15 && x == 31 {
                    break;
                }

                if (block >> x) & 1 == 1 {
                    entries.insert(i as u32 * 32 + x, None);
                }
            }
        }

        Self {
            entries,
            populated: true,
        }
    }

    pub fn entries(&self) -> impl Iterator<Item = (&u32, &Option<String>)> {
        self.entries.iter()
    }

    pub fn get_entry(&self, entry_idx: u32) -> Option<&String> {
        self.entries.get(&entry_idx)?.as_ref()
    }

    pub fn add_entry(&mut self, entry_idx: u32, metadata: String) {
        self.entries.insert(entry_idx, Some(metadata));
    }

    pub fn next_needed_entry_id(&self) -> Option<u32> {
        self.entries
            .iter()
            .find_map(|(entry_idx, data)| data.is_none().then_some(*entry_idx))
    }

    pub fn is_populated(&self) -> bool {
        self.populated
    }
}
