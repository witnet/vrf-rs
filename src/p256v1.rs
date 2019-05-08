use failure::Fail;
use hmac_sha256::HMAC;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcPoint, PointConversionForm},
    error::ErrorStack,
    hash::{hash, MessageDigest},
    nid::Nid,
};
use std::os::raw::c_ulong;

use crate::VRF;

/// The size (in bytes) of a secret key
const SECRET_KEY_SIZE: usize = 32;

/// The size (in bytes) of a serialized public key.
const PUBLIC_KEY_SIZE: usize = 33;

/// Cipher suite for EC p256v1 curve
const P256V1_CIPHER_SUITE: u8 = 0x01;

/// Prefix used for the hash to point function
const HASH_TO_POINT_PREFIX: u8 = 0x01;

/// Prefix used for the hash points function
const HASH_POINTS_PREFIX: u8 = 0x02;

enum Curve {
    NISTP256,
    SECT163K1,
}

/// Error that can be raised when proving/verifying VRFs
#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "Error with code {}", code)]
    CodedError { code: c_ulong },
    #[fail(display = "Hash to point function could not find a valid point")]
    HashToPointError,
    #[fail(display = "Float division error while computing remainder")]
    IntegerDivisionError,
    #[fail(display = "InvalidProofLength")]
    InvalidPiLength,
    #[fail(display = "Unknown error")]
    Unknown,
}

impl From<ErrorStack> for Error {
    fn from(error: ErrorStack) -> Self {
        match error.errors().get(0).map(openssl::error::Error::code) {
            Some(code) => Error::CodedError { code },
            _ => Error::Unknown {},
        }
    }
}

/// Elliptic Curve context
struct ECContext {
    curve: Curve,
    group: EcGroup,
    bn_ctx: BigNumContext,
    order: BigNum,
    hasher: MessageDigest,
    n: usize,
    qlen: usize,
}

/// A Elliptic Curve VRF using the curve p256v1
pub struct ECVRF;

impl<'a> VRF<&'a [u8], &'a [u8]> for ECVRF {
    type Error = Error;

    // Generate proof from key pair and message
    fn prove(x: &[u8], alpha: &[u8]) -> Result<Vec<u8>, Error> {
        let mut ctx = create_ec_context(Curve::NISTP256)?;

        // Step 1: derive public key from secret key
        // Y = x * B
        //TODO: validate secret key length?
        let secret_key = BigNum::from_slice(x)?;
        let public_key_point = derive_public_key(&secret_key, &ctx)?;

        // Step 2: Hash to curve
        let h_point = hash_to_try_and_increment(&public_key_point, alpha, &mut ctx)?;

        // Step 3: point to string
        let h_string =
            h_point.to_bytes(&ctx.group, PointConversionForm::COMPRESSED, &mut ctx.bn_ctx)?;

        // Step 4: Gamma = x * H
        let mut gamma_point = EcPoint::new(&ctx.group.as_ref())?;
        gamma_point.mul(&ctx.group.as_ref(), &h_point, &secret_key, &mut ctx.bn_ctx);

        // Step 5: nonce
        let k = nonce_generation_rfc6979(&secret_key, &h_string, &mut ctx)?;

        // Step 6: c = hash points(...)
        let mut u_point = EcPoint::new(&ctx.group.as_ref())?;
        let mut v_point = EcPoint::new(&ctx.group.as_ref())?;
        u_point.mul_generator(&ctx.group.as_ref(), &k, &mut ctx.bn_ctx);
        v_point.mul(&ctx.group.as_ref(), &h_point, &k, &mut ctx.bn_ctx);
        let mut c = hash_points(&[&h_point, &gamma_point, &u_point, &v_point], &mut ctx)?;

        // Step 7: s = (k + c*x) mod q
        let s = &(&k + &(&c * &secret_key)) % &ctx.order;

        // Step 8: encode (gamma, c, s)
        let gamma_string =
            gamma_point.to_bytes(&ctx.group, PointConversionForm::COMPRESSED, &mut ctx.bn_ctx)?;
        let c_string = append_leading_zeros(&c.to_vec(), ctx.n)?;
        let s_string = append_leading_zeros(&s.to_vec(), ctx.qlen)?;
        let proof = [&gamma_string[..], &c_string, &s_string].concat();

        Ok(proof)
    }
    // Verify proof given public key, proof and message
    fn verify(y: &[u8], pi: &[u8], alpha: &[u8]) -> Result<bool, Error> {
        let mut ctx = create_ec_context(Curve::NISTP256)?;

        // Step 1. decode proof
        let (gamma_point, c, s) =
            decode_proof(&pi, &mut ctx)?;

        // Step 2. hash to curve
        let public_key_point = EcPoint::from_bytes(&ctx.group, &y, &mut ctx.bn_ctx)?;
        let h_point = hash_to_try_and_increment(&public_key_point, alpha, &mut ctx)?;
        println!("{:x?}", h_point.to_bytes(&ctx.group, PointConversionForm::COMPRESSED, &mut ctx.bn_ctx));

        // Step 3: U = sB -cY
        let mut s_b = EcPoint::new(&ctx.group.as_ref())?;
        let mut c_y = EcPoint::new(&ctx.group.as_ref())?;
        let mut u_point = EcPoint::new(&ctx.group.as_ref())?;
        s_b.mul_generator(&ctx.group, &s, &ctx.bn_ctx)?;
        c_y.mul(&ctx.group, &public_key_point, &c, &mut ctx.bn_ctx)?;
        c_y.invert(&ctx.group, &ctx.bn_ctx)?;
        u_point.add(&ctx.group, &s_b, &c_y, &mut ctx.bn_ctx)?;

        // Step 4: V = sH -cGamma
        let mut s_h = EcPoint::new(&ctx.group.as_ref())?;
        let mut c_gamma = EcPoint::new(&ctx.group.as_ref())?;
        let mut v_point = EcPoint::new(&ctx.group.as_ref())?;
        s_h.mul(&ctx.group, &h_point, &s, &mut ctx.bn_ctx)?;
        c_gamma.mul(&ctx.group, &gamma_point, &c, &mut ctx.bn_ctx)?;
        c_gamma.invert(&ctx.group, &ctx.bn_ctx)?;
        v_point.add(&ctx.group, &s_h, &c_gamma, &mut ctx.bn_ctx)?;

        // Step 5: hash points(...)
        let derived_c = hash_points(&[&h_point, &gamma_point, &u_point, &v_point], &mut ctx)?;

        // Step 6: Check validity
        Ok(derived_c.eq(&c))
    }
}

/// Function to create a Elliptic Curve context using the curve prime256v1
fn create_ec_context(curve: Curve) -> Result<ECContext, Error> {
    let group = match curve {
        Curve::NISTP256 => EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?,
        Curve::SECT163K1 => EcGroup::from_curve_name(Nid::SECT163K1)?,
    };
    let mut bn_ctx = BigNumContext::new()?;
    let hasher = MessageDigest::sha256();
    let order = BigNum::new().map(|mut ord| {
        group.order(&mut ord, &mut bn_ctx);
        ord
    })?;

    let mut a = BigNum::new()?;
    let mut b = BigNum::new()?;
    let mut p = BigNum::new()?;
    group.components_gfp(&mut a, &mut b, &mut p, &mut bn_ctx)?;

    let n = ((p.num_bits() + (p.num_bits() % 2)) / 2) as usize;
    let qlen = order.num_bits() as usize;

    Ok(ECContext {
        curve,
        group,
        bn_ctx,
        order,
        hasher,
        n,
        qlen,
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
    public_key: &EcPoint,
    alpha: &[u8],
    mut ctx: &mut ECContext,
) -> Result<EcPoint, Error> {
    let mut c = 0..255;
    let pk_bytes =
        public_key.to_bytes(&ctx.group, PointConversionForm::COMPRESSED, &mut ctx.bn_ctx)?;
    let cipher = [0x01, 0x01];
    let mut v = [&cipher[..], &pk_bytes[..], &alpha[..], &[0x00]].concat();
    let position = v.len() - 1;
    let point = c.find_map(|ctr| {
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

fn append_leading_zeros(data: &[u8], length: usize) -> Result<Vec<u8>, Error> {
    if data.len() * 8 > length {
        return Ok(data.to_vec());
    }

    let leading_zeros = if length % 8 > 0 {
        vec![0; length / 8 + 1 - data.len()]
    } else {
        vec![0; length / 8 - data.len()]
    };
    let padded_bytes = [&leading_zeros[..], &data].concat();

    Ok(padded_bytes)
}

fn decode_proof(pi: &[u8], ctx: &mut ECContext) -> Result<(EcPoint, BigNum, BigNum), Error> {
    let gamma_oct = if ctx.qlen % 8 > 0 {
        ctx.qlen/ 8 + 2
    } else {
        ctx.qlen/ 8 + 1
    };
    let c_oct = if ctx.n % 8 > 0 {
        ctx.n/ 8 + 1
    } else {
        ctx.n/ 8
    };

    if (pi.len()*8 < gamma_oct + c_oct*3){
        return Err(Error::InvalidPiLength);
    }
    let gamma_point = EcPoint::from_bytes(&ctx.group, &pi[0..gamma_oct], &mut ctx.bn_ctx)?;
    let c =  BigNum::from_slice(&pi[gamma_oct..gamma_oct+ c_oct])?;
    let s = BigNum::from_slice(&pi[gamma_oct + c_oct..])?;

    Ok((gamma_point, c, s))
}

fn nonce_generation_rfc6979(
    secret_key: &BigNum,
    data: &[u8],
    ctx: &mut ECContext,
) -> Result<BigNum, Error> {
    // Bits to octets from data - bits2octets(h1)
    // Length of this value should be dependent on qlen (i.e. SECP256k1 is 32)
    let data_trunc = bits2octets(data, ctx)?;
    let padded_data_trunc = append_leading_zeros(&data_trunc, ctx.qlen)?;

    // Bytes to octets from secret key - int2octects(x)
    // Left padding is required for inserting leading zeros
    let padded_secret_key_bytes: Vec<u8> = append_leading_zeros(&secret_key.to_vec(), ctx.qlen)?;

    // Init V & K
    // K = HMAC_K(V || 0x00 || int2octects(secret_key) || bits2octects(data))
    let mut v = [0x01; 32];
    let mut k = [0x00; 32];

    for prefix in 0..2 as u8 {
        k = HMAC::mac(
            [
                &v[..],
                &[prefix],
                &padded_secret_key_bytes[..],
                &padded_data_trunc[..],
            ]
                .concat()
                .as_slice(),
            &k,
        );
        v = HMAC::mac(&v, &k);
    }

    loop {
        v = HMAC::mac(&v, &k);
        let ret_bn = bits2int(&v, ctx.qlen)?;

        if ret_bn > BigNum::from_u32(0)? && ret_bn < ctx.order {
            return Ok(ret_bn);
        }
        k = HMAC::mac([&v[..], &[0x00]].concat().as_slice(), &k);
        v = HMAC::mac(&v, &k);
    }
}

fn bits2octets(data: &[u8], ctx: &mut ECContext) -> Result<Vec<u8>, Error> {
    //FIXME: TO DECIDE WHETHER FOLLOW DIFFERENT TEST VECTORS (qlen for both cases)
    let z1 = match ctx.curve {
        Curve::NISTP256 => bits2int(data, data.len() * 8)?,
        Curve::SECT163K1 => bits2int(data, ctx.qlen)?,
    };
    let result = BigNum::new().and_then(|mut res| {
        res.nnmod(&z1, &ctx.order, &mut ctx.bn_ctx)?;
        Ok(res.to_vec())
    })?;

    Ok(result)
}

/// Transforms slice into Bignum and right-shifts it by len(data)-qlen bits.
fn bits2int(data: &[u8], qlen: usize) -> Result<BigNum, Error> {
    let data_len_bits = data.len() * 8;
    let result = BigNum::from_slice(data).and_then(|data_bn| {
        if data_len_bits > qlen {
            let mut truncated = BigNum::new()?;
            truncated.rshift(&data_bn, (data_len_bits - qlen) as i32)?;

            Ok(truncated)
        } else {
            Ok(data_bn)
        }
    })?;
    let _data2 = data.to_vec();
    let _data_vec = result.to_vec();

    Ok(result)
}

/// Function to calculate the hash of multiple EC Points
fn hash_points(points: &[&EcPoint], ctx: &mut ECContext) -> Result<BigNum, Error> {
    let point_bytes: Result<Vec<u8>, Error> = points.iter().try_fold(
        vec![P256V1_CIPHER_SUITE, HASH_POINTS_PREFIX],
        |mut acc, point| {
            let bytes: Vec<u8> =
                point.to_bytes(&ctx.group, PointConversionForm::COMPRESSED, &mut ctx.bn_ctx)?;
            acc.extend(bytes);

            Ok(acc)
        },
    );
    let to_be_hashed = point_bytes?;
    let mut hash = hash(ctx.hasher, &to_be_hashed).map(|hash| hash.to_vec())?;
    hash.truncate(ctx.n / 8);
    let result = BigNum::from_slice(hash.as_slice())?;

    Ok(result)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_prove_P256_SHA256() {
        // Secret Key (labelled as x)
        let x = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
            .unwrap();

        // Data to be hashed: ASCII "sample
        let alpha = hex::decode("73616d706c65").unwrap();

        let expected_pi = hex::decode("029bdca4cc39e57d97e2f42f88bcf0ecb1120fb67eb408a856050dbfbcbf57c524193b7a850195ef3d5329018a8683114cb446c33fe16ebcc0bc775b043b5860dcb2e553d91268281688438df9394103ab").unwrap();

        let pi = ECVRF::prove(&x, &alpha).unwrap();
        assert_eq!(pi, expected_pi);
    }

    #[test]
    fn test_verify() {
        let y =  hex::decode("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6")
                .unwrap();
        let pi = hex::decode("029bdca4cc39e57d97e2f42f88bcf0ecb1120fb67eb408a856050dbfbcbf57c524193b7a850195ef3d5329018a8683114cb446c33fe16ebcc0bc775b043b5860dcb2e553d91268281688438df9394103ab").unwrap();
        let alpha = hex::decode("73616d706c65").unwrap();


        assert_eq!(ECVRF::verify(&y, &pi, &alpha).unwrap(), true);
    }

    #[test]
    fn test_derive_public_key() {
        let k = [0x01];
        let mut ctx = create_ec_context(Curve::NISTP256).unwrap();

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

    /// Hash to try and increment (TAI) test
    /// Test vector extracted from VRF RFC draft (section A.1)
    #[test]
    fn test_hash_to_try_and_increment() {
        let mut ctx = create_ec_context(Curve::NISTP256).unwrap();
        let public_key_hex =
            hex::decode("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6")
                .unwrap();
        let public_key = EcPoint::from_bytes(&ctx.group, &public_key_hex, &mut ctx.bn_ctx).unwrap();
        let expected_hash_hex =
            hex::decode("02e2e1ab1b9f5a8a68fa4aad597e7493095648d3473b213bba120fe42d1a595f3e")
                .unwrap();
        let expected_hash =
            EcPoint::from_bytes(&ctx.group, &expected_hash_hex, &mut ctx.bn_ctx).unwrap();
        // Data to be hashed: ASCII "sample
        let data = hex::decode("73616d706c65").unwrap();
        let derived_hash = hash_to_try_and_increment(&public_key, &data, &mut ctx).unwrap();
        assert!(derived_hash
            .eq(&ctx.group, &expected_hash, &mut ctx.bn_ctx)
            .unwrap());
    }

    #[test]
    fn test_hash_to_try_and_increment_2() {
        // Example of using a different hashing function
        let suite: u8 = 1;
        let mut ctx = create_ec_context(Curve::NISTP256).unwrap();
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
        let derived_hash = hash_to_try_and_increment(&public_key, &data, &mut ctx).unwrap();
        assert!(derived_hash
            .eq(&ctx.group, &expected_hash, &mut ctx.bn_ctx)
            .unwrap());
    }

    /// Nonce generation test using the curve K-163
    /// Test vector extracted from RFC6979 (section A.1)
    #[test]
    fn test_nonce_generation_RFC6979_SECT163K1() {
        let mut ctx = create_ec_context(Curve::SECT163K1).unwrap();
        let mut ord = BigNum::new().unwrap();
        ctx.group.order(&mut ord, &mut ctx.bn_ctx).unwrap();

        // Expected result/nonce (labelled as K or T)
        // This is the va;ue of T
        let expected_nonce = hex::decode("023AF4074C90A02B3FE61D286D5C87F425E6BDD81B").unwrap();

        // Secret Key (labelled as x)
        let sk = hex::decode("009A4D6792295A7F730FC3F2B49CBC0F62E862272F").unwrap();
        let sk_bn = BigNum::from_slice(&sk).unwrap();

        // Hashed input message (labelled as h1)
        let data = hex::decode("AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF")
            .unwrap();
        let data_bn = BigNum::from_slice(&data).unwrap();

        // Nonce generation
        let derived_nonce = nonce_generation_rfc6979(&sk_bn, &data, &mut ctx).unwrap();

        assert_eq!(derived_nonce.to_vec(), expected_nonce);
    }

    #[test]
    fn test_nonce_generation_RFC6979_NISTP256() {
        let mut ctx = create_ec_context(Curve::NISTP256).unwrap();
        let mut ord = BigNum::new().unwrap();
        let mut a = BigNum::new().unwrap();
        let mut b = BigNum::new().unwrap();
        let mut p = BigNum::new().unwrap();
        ctx.group
            .components_gfp(&mut a, &mut b, &mut p, &mut ctx.bn_ctx)
            .unwrap();

        // Expected result/nonce (labelled as K or T)
        // This is the va;ue of T
        let expected_nonce =
            hex::decode("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60")
                .unwrap();

        // Secret Key (labelled as x)
        let sk = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
            .unwrap();
        let sk_bn = BigNum::from_slice(&sk).unwrap();

        // Hashed input message (labelled as h1)
        //FIXME: TO CHECK if 0x02 is correct
        let data = hex::decode("AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF")
            .unwrap();
        let data_bn = BigNum::from_slice(&data).unwrap();

        // Nonce generation
        let derived_nonce = nonce_generation_rfc6979(&sk_bn, &data, &mut ctx).unwrap();
        assert_eq!(derived_nonce.to_vec(), expected_nonce);
    }

    #[test]
    fn test_nonce_generation_RFC6979_NISTP256_2() {
        let mut ctx = create_ec_context(Curve::NISTP256).unwrap();
        let mut ord = BigNum::new().unwrap();
        ctx.group.order(&mut ord, &mut ctx.bn_ctx).unwrap();
        // Expected result/nonce (labelled as K or T)
        // This is the value of T
        let expected_nonce =
            hex::decode("D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0")
                .unwrap();

        // Secret Key (labelled as x)
        let sk = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
            .unwrap();
        let sk_bn = BigNum::from_slice(&sk).unwrap();

        // Hashed input message (labelled as h1)
        //FIXME: TO CHECK if 0x02 is correct
        let data = hex::decode("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
            .unwrap();
        let data_bn = BigNum::from_slice(&data).unwrap();

        // Nonce generation
        let derived_nonce = nonce_generation_rfc6979(&sk_bn, &data, &mut ctx).unwrap();
        assert_eq!(derived_nonce.to_vec(), expected_nonce);
    }

    #[test]
    fn test_nonce_generation_RFC6979_NISTP256_3() {
        let mut ctx = create_ec_context(Curve::NISTP256).unwrap();
        let mut ord = BigNum::new().unwrap();
        ctx.group.order(&mut ord, &mut ctx.bn_ctx).unwrap();
        // Expected result/nonce (labelled as K or T)
        // This is the va;ue of T
        let expected_nonce =
            hex::decode("c1aba586552242e6b324ab4b7b26f86239226f3cfa85b1c3b675cc061cf147dc")
                .unwrap();

        // Secret Key (labelled as x)
        let sk = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
            .unwrap();
        let sk_bn = BigNum::from_slice(&sk).unwrap();

        // Hashed input message (labelled as h1)
        //FIXME: TO CHECK if 0x02 is correct
        let data =
            hex::decode("02e2e1ab1b9f5a8a68fa4aad597e7493095648d3473b213bba120fe42d1a595f3e")
                .unwrap();
        let data_bn = BigNum::from_slice(&data).unwrap();

        // Nonce generation
        let derived_nonce = nonce_generation_rfc6979(&sk_bn, &data, &mut ctx).unwrap();

        assert_eq!(derived_nonce.to_vec(), expected_nonce);
    }

    #[test]
    fn test_bits2int() {
        let mut ctx = create_ec_context(Curve::NISTP256).unwrap();
        let data1 = vec![0x01; 32];
        let data1_bn = BigNum::from_slice(&data1).unwrap();
        let result1 = bits2int(&data1, 256).unwrap();
        assert_eq!(data1_bn, result1);

        let data2 = vec![0x01; 33];
        let data2_bn = BigNum::from_slice(&data2).unwrap();
        let result2 = bits2int(&data2, 256).unwrap();
        let mut truncated = BigNum::new().unwrap();
        truncated.rshift(&data2_bn, 8);
        assert_eq!(truncated.to_vec(), result2.to_vec());
    }

    #[test]
    fn test_hash_points() {
        let mut ctx = create_ec_context(Curve::NISTP256).unwrap();

        let hash_hex =
            hex::decode("02e2e1ab1b9f5a8a68fa4aad597e7493095648d3473b213bba120fe42d1a595f3e")
                .unwrap();
        let hash_point = EcPoint::from_bytes(&ctx.group, &hash_hex, &mut ctx.bn_ctx).unwrap();

        let pi_hex = hex::decode("029bdca4cc39e57d97e2f42f88bcf0ecb1120fb67eb408a856050dbfbcbf57c524193b7a850195ef3d5329018a8683114cb446c33fe16ebcc0bc775b043b5860dcb2e553d91268281688438df9394103ab")
            .unwrap();
        let mut gamma_hex = pi_hex.clone();
        let c_s_hex = gamma_hex.split_off(33);
        let gamma_point = EcPoint::from_bytes(&ctx.group, &gamma_hex, &mut ctx.bn_ctx).unwrap();

        let mut c_hex = c_s_hex.clone();
        c_hex.split_off(16);

        let u_hex =
            hex::decode("02007fe22a3ed063db835a63a92cb1e487c4fea264c3f3700ae105f8f3d3fd391f")
                .unwrap();
        let u_point = EcPoint::from_bytes(&ctx.group, &u_hex, &mut ctx.bn_ctx).unwrap();

        let v_hex =
            hex::decode("03d0a63fa7a7fefcc590cb997b21bbd21dc01304102df183fb7115adf6bcbc2a74")
                .unwrap();
        let v_point = EcPoint::from_bytes(&ctx.group, &v_hex, &mut ctx.bn_ctx).unwrap();

        let computed_c =
            hash_points(&[&hash_point, &gamma_point, &u_point, &v_point], &mut ctx).unwrap();

        assert_eq!(computed_c.to_vec(), c_hex);
    }
    #[test]
    fn test_decode_proof() {
        let mut ctx = create_ec_context(Curve::NISTP256).unwrap();


        let pi_hex = hex::decode("029bdca4cc39e57d97e2f42f88bcf0ecb1120fb67eb408a856050dbfbcbf57c524193b7a850195ef3d5329018a8683114cb446c33fe16ebcc0bc775b043b5860dcb2e553d91268281688438df9394103ab")
            .unwrap();

        let (derived_gamma, derived_c, derived_s) =
            decode_proof(&pi_hex, &mut ctx).unwrap();

        let mut gamma_hex = pi_hex.clone();
        let c_s_hex = gamma_hex.split_off(33);
        let gamma_point = EcPoint::from_bytes(&ctx.group, &gamma_hex, &mut ctx.bn_ctx).unwrap();

        let mut c_hex = c_s_hex.clone();
        c_hex.split_off(16);
        let c = BigNum::from_slice(c_hex.as_slice()).unwrap();

        assert!(derived_c.eq(&c));
        assert!(gamma_point
            .eq(&ctx.group, &derived_gamma, &mut ctx.bn_ctx)
            .unwrap());
    }
}
