pub use aucpace::StrongDatabase;

use aucpace::PartialAugDatabase;
use curve25519_dalek::Scalar;

use curve25519_dalek::RistrettoPoint;
use password_hash::ParamsString;

/// Password Verifier database which can store the info for one user
#[derive(Default)]
pub struct SingleUserDatabase<const USERSIZE: usize> {
    user: Option<([u8; USERSIZE], usize)>,
    data: Option<(RistrettoPoint, Scalar, ParamsString)>,
    long_term_keypair: Option<(Scalar, RistrettoPoint)>,
}

impl<const USERSIZE: usize> StrongDatabase for SingleUserDatabase<USERSIZE> {
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

        if username.len() <= USERSIZE {
            let mut buf = [0u8; USERSIZE];
            buf[..username.len()].copy_from_slice(username);
            self.user = Some((buf, username.len()));
            self.data = Some((verifier, secret_exponent, params));
        }
    }
}

impl<const USERSIZE: usize> PartialAugDatabase for SingleUserDatabase<USERSIZE> {
    type PrivateKey = Scalar;
    type PublicKey = RistrettoPoint;

    fn lookup_long_term_keypair(
        &self,
        username: &[u8],
    ) -> Option<(Self::PrivateKey, Self::PublicKey)> {
        match self.user {
            Some((ref stored_username, len)) if &stored_username[..len] == username => {
                self.long_term_keypair.clone()
            }
            _ => None,
        }
    }

    fn store_long_term_keypair(
        &mut self,
        username: &[u8],
        priv_key: Self::PrivateKey,
        pub_key: Self::PublicKey,
    ) -> aucpace::Result<()> {
        match self.user {
            Some((ref stored_user, len)) if &stored_user[..len] == username => {
                self.long_term_keypair = Some((priv_key, pub_key));
                Ok(())
            }
            _ => Err(aucpace::Error::UserNotRegistered),
        }
    }
}
