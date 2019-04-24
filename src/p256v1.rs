use std::os::raw::c_ulong;

use failure::Fail;
use openssl::error::ErrorStack;

use crate::VRF;

/// The size (in bytes) of a secret key
pub const SECRET_KEY_SIZE: usize = 32;

/// The size (in bytes) of a serialized public key.
pub const PUBLIC_KEY_SIZE: usize = 33;

/// The type of the secret key
pub type SecretKey<'a> = &'a [u8; SECRET_KEY_SIZE];

/// The type of the public key
pub type PublicKey<'a> = &'a [u8; PUBLIC_KEY_SIZE];

/// Error that can be raised when proving/verifying VRFs
#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "Error with code {}", code)]
    CodedError { code: c_ulong },
    #[fail(display = "Unknown error")]
    Unknown,
}

impl From<ErrorStack> for Error {
    fn from(error: ErrorStack) -> Self {
        match error.errors().get(0).map(|e| e.code()) {
            Some(code) => Error::CodedError { code },
            _ => Error::Unknown {},
        }
    }
}

/// A Elliptic Curve VRF using the curve p256v1
struct P256v1;

impl<'a> VRF<PublicKey<'a>, SecretKey<'a>> for P256v1 {
    type Error = Error;

    // Generate proof from key pair and message
    fn prove(_x: SecretKey, _alpha: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(vec![])
    }

    // Verify proof given public key, proof and message
    fn verify(_y: PublicKey, _pi: &[u8], _alpha: &[u8]) -> Result<bool, Error> {
        Ok(false)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_prove() {
        let x = [0; 32];
        let alpha = [0, 0, 0];

        let proof = P256v1::prove(&x, &alpha);
        assert_eq!(proof.unwrap(), vec![]);
    }

    #[test]
    fn test_verify() {
        let y = [0; 33];
        let pi = [0];
        let alpha = [0, 0, 0];

        assert_eq!(P256v1::verify(&y, &pi, &alpha).unwrap(), false);
    }
}
