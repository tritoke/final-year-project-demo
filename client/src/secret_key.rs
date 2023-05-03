use anyhow::ensure;
use rand_core::{CryptoRngCore, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

const SK_ALPHABET: &[u8; 31] = b"23456789ABCDEFGHJKLMNPQRSTVWXYZ";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretKey {
    #[serde(with = "serde_byte_array")]
    inner: [u8; 26],
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl SecretKey {
    pub fn generate(csprng: &mut impl CryptoRngCore) -> Self {
        let mut positions = [0u8; 26];
        csprng.fill_bytes(&mut positions);

        // clip the values
        for b in positions.iter_mut() {
            loop {
                // we do this to avoid bias
                if *b & 0x1F == 0x1F {
                    *b = csprng.next_u64() as u8;
                } else {
                    *b = SK_ALPHABET[(*b % 0x1F) as usize];
                    break;
                }
            }
        }

        Self { inner: positions }
    }
}

impl Display for SecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = std::str::from_utf8(&self.inner).expect("UTF8 invariant broken");
        write!(
            f,
            "{}-{}-{}-{}-{}",
            &s[0..6],
            &s[6..11],
            &s[11..16],
            &s[16..21],
            &s[21..26],
        )
    }
}

impl FromStr for SecretKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ensure!(
            s.chars().all(
                |c| matches!(c, '2'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='T' | 'V'..='Z' | '-')
            ),
            "Bad secret key - invalid format1"
        );
        let parts: Vec<_> = s.split('-').collect();

        ensure!(parts.len() == 5, "Bad secret key - invalid format2");
        ensure!(
            parts[0].len() == 6
                && parts[1].len() == 5
                && parts[2].len() == 5
                && parts[3].len() == 5
                && parts[4].len() == 5,
            "Bad secret key - invalid format3"
        );

        let bytes: Vec<_> = parts.iter().flat_map(|part| part.bytes()).collect();
        let inner = bytes.try_into().expect("Length invariant broken");
        Ok(Self { inner })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_parse_secret_key() {
        let sk = "JPTVZX-92346-23456-32345-ABCDA";
        let parsed = sk.parse::<SecretKey>().unwrap();
        let correct = SecretKey {
            inner: [
                74, 80, 84, 86, 90, 88, 57, 50, 51, 52, 54, 50, 51, 52, 53, 54, 51, 50, 51, 52, 53,
                65, 66, 67, 68, 65,
            ],
        };
        assert_eq!(parsed, correct);
    }

    #[test]
    fn test_format_secret_key() {
        let correct = "JPTVZX-92346-23456-32345-ABCDA";
        let sk = SecretKey {
            inner: [
                74, 80, 84, 86, 90, 88, 57, 50, 51, 52, 54, 50, 51, 52, 53, 54, 51, 50, 51, 52, 53,
                65, 66, 67, 68, 65,
            ],
        };
        assert_eq!(format!("{sk}"), correct);
    }

    #[test]
    fn test_generate_secret_key() {
        let mut rng = OsRng;
        for _ in 0..100 {
            let sk = SecretKey::generate(&mut rng);
            assert_eq!(sk, format!("{sk}").parse::<SecretKey>().unwrap());
        }
    }
}
