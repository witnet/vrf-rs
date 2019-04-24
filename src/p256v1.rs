use std::os::raw::c_ulong;

use failure::Fail;
use hex::FromHex;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcPoint, PointConversionForm},
    error::ErrorStack,
    hash::{hash, MessageDigest},
    nid::Nid,
};

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
    #[fail(display = "Hash to point function could not find a valid point")]
    HashToPointError,
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

/// Elliptic Curve context
struct ECContext {
    group: EcGroup,
    bn_ctx: BigNumContext,
    hasher: MessageDigest,
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

/// Function to create a Elliptic Curve context using the curve prime256v1
fn create_ec_context() -> Result<ECContext, Error> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let bn_ctx = BigNumContext::new()?;
    let hasher = MessageDigest::sha256();

    Ok(ECContext {
        group,
        bn_ctx,
        hasher,
    })
}

/// Function for deriving public key given a secret key point
fn derive_public_key(secret_key: &BigNum, ctx: &ECContext) -> Result<EcPoint, Error> {
    let mut point = EcPoint::new(&ctx.group.as_ref())?;
    point.mul_generator(&ctx.group, &secret_key, &ctx.bn_ctx)?;
    Ok(point)
}

/// Function to convert a Hash(PK|DATA) to a point in the curve
fn hash_to_try_and_increment(
    suite_string: &u8,
    public_key: &EcPoint,
    alpha: &[u8],
    mut ctx: &mut ECContext,
) -> Result<EcPoint, Error> {
    let c = 0..255;
    let pk_bytes =
        public_key.to_bytes(&ctx.group, PointConversionForm::COMPRESSED, &mut ctx.bn_ctx)?;
    let mut v = vec![];
    let cipher = [0x01, 0x01];
    v.extend(&cipher);
    v.extend(pk_bytes.clone());
    v.extend(alpha.clone());
    v.push(0);
    let position = v.len() - 1;
    let point = c.into_iter().find_map(|ctr| {
        v[position] = ctr;
        let attempted_hash = hash(ctx.hasher, &v);
        match attempted_hash {
            Ok(attempted_hash) => arbitrary_string_to_point(&attempted_hash, &mut ctx).ok(),
            _ => None,
        }
    });
    point.ok_or(Error::HashToPointError)
}

/// Function for converting a string to a point in the curve
fn arbitrary_string_to_point(data: &[u8], ctx: &mut ECContext) -> Result<EcPoint, Error> {
    let mut v = vec![0x02];
    v.extend(data);
    let point = EcPoint::from_bytes(&ctx.group, &v, &mut ctx.bn_ctx)?;
    Ok(point)
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

    #[test]
    fn test_derive_public_key() {
        // Example of using a different hashing function

        let k = [0x01];
        let mut ctx = create_ec_context().unwrap();

        let secret_key = BigNum::from_slice(&k).unwrap();
        let expected = [
            0x03, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63,
            0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39,
            0x45, 0xD8, 0x98, 0xC2, 0x96,
        ];
        let derived_public_key = derive_public_key(&secret_key, &ctx).unwrap();
        let expected_point = EcPoint::from_bytes(&ctx.group, &expected, &mut ctx.bn_ctx).unwrap();
        assert!(derived_public_key
            .eq(&ctx.group, &expected_point, &mut ctx.bn_ctx)
            .unwrap());
    }

    #[test]
    fn test_hash_to_try_and_increment() {
        // Example of using a different hashing function
        let suite: u8 = 1;
        let mut ctx = create_ec_context().unwrap();
        let public_key_hex =
            hex::decode("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6")
                .unwrap();
        let public_key = EcPoint::from_bytes(&ctx.group, &public_key_hex, &mut ctx.bn_ctx).unwrap();
        let expected_hash_hex =
            hex::decode("02e2e1ab1b9f5a8a68fa4aad597e7493095648d3473b213bba120fe42d1a595f3e")
                .unwrap();
        let expected_hash =
            EcPoint::from_bytes(&ctx.group, &expected_hash_hex, &mut ctx.bn_ctx).unwrap();
        let data = hex::decode("73616d706c65").unwrap();
        let derived_hash = hash_to_try_and_increment(&suite, &public_key, &data, &mut ctx).unwrap();
        assert!(derived_hash
            .eq(&ctx.group, &expected_hash, &mut ctx.bn_ctx)
            .unwrap());
    }

    #[test]
    fn test_hash_to_try_and_increment_2() {
        // Example of using a different hashing function
        let suite: u8 = 1;
        let mut ctx = create_ec_context().unwrap();
        let public_key_hex =
            hex::decode("03596375e6ce57e0f20294fc46bdfcfd19a39f8161b58695b3ec5b3d16427c274d")
                .unwrap();
        let public_key = EcPoint::from_bytes(&ctx.group, &public_key_hex, &mut ctx.bn_ctx).unwrap();
        let expected_hash_hex =
            hex::decode("02141e41d4d55802b0e3adaba114c81137d95fd3869b6b385d4487b1130126648d")
                .unwrap();
        let expected_hash =
            EcPoint::from_bytes(&ctx.group, &expected_hash_hex, &mut ctx.bn_ctx).unwrap();
        let data = hex::decode("4578616d706c65206f66204543445341207769746820616e736970323536723120616e64205348412d323536").unwrap();
        let derived_hash = hash_to_try_and_increment(&suite, &public_key, &data, &mut ctx).unwrap();
        assert!(derived_hash
            .eq(&ctx.group, &expected_hash, &mut ctx.bn_ctx)
            .unwrap());
    }
}
