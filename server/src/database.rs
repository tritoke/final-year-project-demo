pub use aucpace::StrongDatabase;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::Scalar;

use curve25519_dalek::RistrettoPoint;
use password_hash::ParamsString;

pub const MAX_USERNAME_LEN: usize = 37;

/// Password Verifier database which can store the info for one user
#[derive(Default)]
pub struct SingleUserDatabase {
    user: Option<([u8; MAX_USERNAME_LEN], usize)>,
    data: Option<(RistrettoPoint, Scalar, ParamsString)>,
}

impl SingleUserDatabase {
    pub fn is_populated(&self) -> bool {
        self.user.is_some() && self.data.is_some()
    }

    // format: [verifier][q][params][0*][username][0*]
    pub fn serialise(&self) -> [u8; 228] {
        let mut buf = [0u8; 228];
        if let Some((verifier, q, params)) = &self.data {
            buf[0..32].copy_from_slice(verifier.compress().as_bytes());
            buf[32..64].copy_from_slice(q.as_bytes());
            // pb can be at most MAX_LENGTH - 127
            let pb = params.as_bytes();
            buf[64..64 + pb.len()].copy_from_slice(pb);
        }

        if let Some((user, userlen)) = self.user {
            // 191 = 64 + 127
            buf[191..191 + userlen].copy_from_slice(&user[..userlen]);
        }

        buf
    }

    pub fn deserialise(buf: &[u8; 228]) -> Option<Self> {
        // parse the verifier
        let verifier = CompressedRistretto::from_slice(&buf[0..32])
            .ok()?
            .decompress()?;

        // parse q
        let q_bytes = buf[32..64].try_into().expect("length invariant broken");
        // poor man's ? operator
        let q_option = Scalar::from_canonical_bytes(q_bytes);
        if q_option.is_none().into() {
            return None;
        }
        let q = q_option.unwrap();

        // parse params
        let params_end = (64..191).find(|i| buf[*i] == 0).unwrap_or(191);
        let params_str = core::str::from_utf8(&buf[64..params_end]).ok()?;
        let params = params_str.parse().ok()?;

        // parse the username
        let username_end = (191..228).find(|i| buf[*i] == 0).unwrap_or(228);
        let username = buf[191..228].try_into().expect("length invariant broken");
        let username_len = username_end - 191;

        Some(SingleUserDatabase {
            user: Some((username, username_len)),
            data: Some((verifier, q, params)),
        })
    }
}

impl StrongDatabase for SingleUserDatabase {
    type PasswordVerifier = RistrettoPoint;
    type Exponent = Scalar;

    fn lookup_verifier_strong(
        &self,
        username: &[u8],
    ) -> Option<(Self::PasswordVerifier, Self::Exponent, ParamsString)> {
        match self.user {
            Some((ref stored_username, len)) if &stored_username[..len] == username => {
                self.data.clone()
            }
            _ => None,
        }
    }

    fn store_verifier_strong(
        &mut self,
        username: &[u8],
        _uad: Option<&[u8]>,
        verifier: Self::PasswordVerifier,
        secret_exponent: Self::Exponent,
        params: ParamsString,
    ) {
        // only allow registration once
        if self.user.is_some() {
            return;
        }

        if username.len() <= MAX_USERNAME_LEN {
            let mut buf = [0u8; MAX_USERNAME_LEN];
            buf[..username.len()].copy_from_slice(username);
            self.user = Some((buf, username.len()));
            self.data = Some((verifier, secret_exponent, params));
        }
    }
}
