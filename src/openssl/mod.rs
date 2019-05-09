use std::os::raw::c_ulong;

use failure::Fail;
use hmac_sha256::HMAC;

use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcPoint, PointConversionForm},
    error::ErrorStack,
    hash::{hash, MessageDigest},
    nid::Nid,
};

use crate::VRF;

use self::utils::{append_leading_zeros, bits2int, bits2octets};

mod utils;

#[allow(non_camel_case_types)]
pub enum CipherSuite {
    P256_SHA256_TAI,
    K163_SHA256_TAI,
}

impl CipherSuite {
    fn suite_string(&self) -> u8 {
        match *self {
            CipherSuite::P256_SHA256_TAI => 0x01,
            CipherSuite::K163_SHA256_TAI => 0xFF,
        }
    }
}

/// Error that can be raised when proving/verifying VRFs
#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "Error with code {}", code)]
    CodedError { code: c_ulong },
    #[fail(display = "Hash to point function could not find a valid point")]
    HashToPointError,
    #[fail(display = "InvalidProofLength")]
    InvalidPiLength,
    #[fail(display = "InvalidProof")]
    InvalidProof,
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

/// A Elliptic Curve VRF
pub struct ECVRF {
    bn_ctx: BigNumContext,
    cipher_suite: CipherSuite,
    group: EcGroup,
    hasher: MessageDigest,
    order: BigNum,
    qlen: usize,
    n: usize,
}

impl ECVRF {
    /// Function to create a Elliptic Curve context using the curve prime256v1
    pub fn from_suite(suite: CipherSuite) -> Result<Self, Error> {
        let group = match suite {
            CipherSuite::P256_SHA256_TAI => EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?,
            CipherSuite::K163_SHA256_TAI => EcGroup::from_curve_name(Nid::SECT163K1)?,
        };
        let mut bn_ctx = BigNumContext::new()?;
        let hasher = MessageDigest::sha256();
        let mut order = BigNum::new()?;
        group.order(&mut order, &mut bn_ctx)?;

        let mut a = BigNum::new()?;
        let mut b = BigNum::new()?;
        let mut p = BigNum::new()?;
        group.components_gfp(&mut a, &mut b, &mut p, &mut bn_ctx)?;

        let n = ((p.num_bits() + (p.num_bits() % 2)) / 2) as usize;
        let qlen = order.num_bits() as usize;

        Ok(ECVRF {
            cipher_suite: suite,
            group,
            bn_ctx,
            order,
            hasher,
            n,
            qlen,
        })
    }

    /// Function for deriving public key given a secret key point
    fn derive_public_key(&mut self, secret_key: &BigNum) -> Result<EcPoint, Error> {
        let mut point = EcPoint::new(&self.group.as_ref())?;
        point.mul_generator(&self.group, &secret_key, &self.bn_ctx)?;
        Ok(point)
    }

    //TODO: add documentation (all)
    fn generate_nonce(&mut self, secret_key: &BigNum, data: &[u8]) -> Result<BigNum, Error> {
        // Bits to octets from data - bits2octets(h1)
        // Length of this value should be dependent on qlen (i.e. SECP256k1 is 32)
        //FIXME: HACK!
        let hacked_qlen = match self.cipher_suite {
            CipherSuite::P256_SHA256_TAI => data.len() * 8,
            CipherSuite::K163_SHA256_TAI => self.qlen,
        };

        let data_trunc = bits2octets(data, hacked_qlen, &self.order, &mut self.bn_ctx)?;
        let padded_data_trunc = append_leading_zeros(&data_trunc, self.qlen);

        // Bytes to octets from secret key - int2octects(x)
        // Left padding is required for inserting leading zeros
        let padded_secret_key_bytes: Vec<u8> =
            append_leading_zeros(&secret_key.to_vec(), self.qlen);

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
            let ret_bn = bits2int(&v, self.qlen)?;

            if ret_bn > BigNum::from_u32(0)? && ret_bn < self.order {
                return Ok(ret_bn);
            }
            k = HMAC::mac([&v[..], &[0x00]].concat().as_slice(), &k);
            v = HMAC::mac(&v, &k);
        }
    }

    //TODO: check documentation (all)
    /// Function to convert a Hash(PK|DATA) to a point in the curve
    fn hash_to_try_and_increment(
        &mut self,
        public_key: &EcPoint,
        alpha: &[u8],
    ) -> Result<EcPoint, Error> {
        let mut c = 0..255;
        let pk_bytes = public_key.to_bytes(
            &self.group,
            PointConversionForm::COMPRESSED,
            &mut self.bn_ctx,
        )?;
        let cipher = [self.cipher_suite.suite_string(), 0x01];
        let mut v = [&cipher[..], &pk_bytes[..], &alpha[..], &[0x00]].concat();
        let position = v.len() - 1;
        let point = c.find_map(|ctr| {
            v[position] = ctr;
            let attempted_hash = hash(self.hasher, &v);
            match attempted_hash {
                Ok(attempted_hash) => self.arbitrary_string_to_point(&attempted_hash).ok(),
                _ => None,
            }
        });
        point.ok_or(Error::HashToPointError)
    }

    //TODO: check documentation (ec, bn - bn_ctx, ec_ctx)
    /// Function for converting a string to a point in the curve
    fn arbitrary_string_to_point(&mut self, data: &[u8]) -> Result<EcPoint, Error> {
        let mut v = vec![0x02];
        v.extend(data);
        let point = EcPoint::from_bytes(&self.group, &v, &mut self.bn_ctx)?;
        Ok(point)
    }

    //TODO: check documentation (ec, bn - bn_ctx, ec_ctx)
    /// Function to calculate the hash of multiple EC Points
    fn hash_points(&mut self, points: &[&EcPoint]) -> Result<BigNum, Error> {
        let point_bytes: Result<Vec<u8>, Error> = points.iter().try_fold(
            vec![self.cipher_suite.suite_string(), 0x02],
            |mut acc, point| {
                let bytes: Vec<u8> = point.to_bytes(
                    &self.group,
                    PointConversionForm::COMPRESSED,
                    &mut self.bn_ctx,
                )?;
                acc.extend(bytes);

                Ok(acc)
            },
        );
        let to_be_hashed = point_bytes?;
        let mut hash = hash(self.hasher, &to_be_hashed).map(|hash| hash.to_vec())?;
        hash.truncate(self.n / 8);
        let result = BigNum::from_slice(hash.as_slice())?;

        Ok(result)
    }

    fn decode_proof(&mut self, pi: &[u8]) -> Result<(EcPoint, BigNum, BigNum), Error> {
        let gamma_oct = if self.qlen % 8 > 0 {
            self.qlen / 8 + 2
        } else {
            self.qlen / 8 + 1
        };
        let c_oct = if self.n % 8 > 0 {
            self.n / 8 + 1
        } else {
            self.n / 8
        };

        if pi.len() * 8 < gamma_oct + c_oct * 3 {
            return Err(Error::InvalidPiLength);
        }
        let gamma_point = EcPoint::from_bytes(&self.group, &pi[0..gamma_oct], &mut self.bn_ctx)?;
        let c = BigNum::from_slice(&pi[gamma_oct..gamma_oct + c_oct])?;
        let s = BigNum::from_slice(&pi[gamma_oct + c_oct..])?;

        Ok((gamma_point, c, s))
    }

    fn proof_to_hash(&mut self, gamma: &EcPoint) -> Result<Vec<u8>, Error> {
        let gamma_string = gamma.to_bytes(
            &self.group,
            PointConversionForm::COMPRESSED,
            &mut self.bn_ctx,
        )?;
        let hash = hash(
            self.hasher,
            &[
                &[self.cipher_suite.suite_string()],
                &[0x03],
                &gamma_string[..],
            ]
            .concat(),
        )
        .map(|hash| hash.to_vec())?;

        Ok(hash)
    }
}

impl VRF<&[u8], &[u8]> for ECVRF {
    type Error = Error;

    // Generate proof from key pair and message
    fn prove(&mut self, x: &[u8], alpha: &[u8]) -> Result<Vec<u8>, Error> {
        // Step 1: derive public key from secret key
        // Y = x * B
        //TODO: validate secret key length?
        let secret_key = BigNum::from_slice(x)?;
        let public_key_point = self.derive_public_key(&secret_key)?;

        // Step 2: Hash to curve
        let h_point = self.hash_to_try_and_increment(&public_key_point, alpha)?;

        // Step 3: point to string
        let h_string = h_point.to_bytes(
            &self.group,
            PointConversionForm::COMPRESSED,
            &mut self.bn_ctx,
        )?;

        // Step 4: Gamma = x * H
        let mut gamma_point = EcPoint::new(&self.group.as_ref())?;
        gamma_point.mul(&self.group.as_ref(), &h_point, &secret_key, &self.bn_ctx)?;

        // Step 5: nonce
        let k = self.generate_nonce(&secret_key, &h_string)?;

        // Step 6: c = hash points(...)
        let mut u_point = EcPoint::new(&self.group.as_ref())?;
        let mut v_point = EcPoint::new(&self.group.as_ref())?;
        u_point.mul_generator(&self.group.as_ref(), &k, &self.bn_ctx)?;
        v_point.mul(&self.group.as_ref(), &h_point, &k, &self.bn_ctx)?;
        let c = self.hash_points(&[&h_point, &gamma_point, &u_point, &v_point])?;

        // Step 7: s = (k + c*x) mod q
        let s = &(&k + &(&c * &secret_key)) % &self.order;

        // Step 8: encode (gamma, c, s)
        let gamma_string = gamma_point.to_bytes(
            &self.group,
            PointConversionForm::COMPRESSED,
            &mut self.bn_ctx,
        )?;
        let c_string = append_leading_zeros(&c.to_vec(), self.n);
        let s_string = append_leading_zeros(&s.to_vec(), self.qlen);
        let proof = [&gamma_string[..], &c_string, &s_string].concat();

        Ok(proof)
    }
    // Verify proof given public key, proof and message
    fn verify(&mut self, y: &[u8], pi: &[u8], alpha: &[u8]) -> Result<Vec<u8>, Error> {
        // Step 1. decode proof
        let (gamma_point, c, s) = self.decode_proof(&pi)?;

        // Step 2. hash to curve
        let public_key_point = EcPoint::from_bytes(&self.group, &y, &mut self.bn_ctx)?;
        let h_point = self.hash_to_try_and_increment(&public_key_point, alpha)?;

        // Step 3: U = sB -cY
        let mut s_b = EcPoint::new(&self.group.as_ref())?;
        let mut c_y = EcPoint::new(&self.group.as_ref())?;
        let mut u_point = EcPoint::new(&self.group.as_ref())?;
        s_b.mul_generator(&self.group, &s, &self.bn_ctx)?;
        c_y.mul(&self.group, &public_key_point, &c, &self.bn_ctx)?;
        c_y.invert(&self.group, &self.bn_ctx)?;
        u_point.add(&self.group, &s_b, &c_y, &mut self.bn_ctx)?;

        // Step 4: V = sH -cGamma
        let mut s_h = EcPoint::new(&self.group.as_ref())?;
        let mut c_gamma = EcPoint::new(&self.group.as_ref())?;
        let mut v_point = EcPoint::new(&self.group.as_ref())?;
        s_h.mul(&self.group, &h_point, &s, &self.bn_ctx)?;
        c_gamma.mul(&self.group, &gamma_point, &c, &self.bn_ctx)?;
        c_gamma.invert(&self.group, &self.bn_ctx)?;
        v_point.add(&self.group, &s_h, &c_gamma, &mut self.bn_ctx)?;

        // Step 5: hash points(...)
        let derived_c = self.hash_points(&[&h_point, &gamma_point, &u_point, &v_point])?;

        // Step 6: Check validity
        if !derived_c.eq(&c) {
            return Err(Error::InvalidProof);
        }
        let beta = self.proof_to_hash(&gamma_point)?;

        Ok(beta)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_prove_p256_sha256_tai_1() {
        let mut ecvrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();
        // Secret Key (labelled as x)
        let x = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
            .unwrap();
        // Data to be hashed: ASCII "sample
        let alpha = hex::decode("73616d706c65").unwrap();
        let expected_pi = hex::decode("029bdca4cc39e57d97e2f42f88bcf0ecb1120fb67eb408a856050dbfbcbf57c524193b7a850195ef3d5329018a8683114cb446c33fe16ebcc0bc775b043b5860dcb2e553d91268281688438df9394103ab").unwrap();
        let pi = ecvrf.prove(&x, &alpha).unwrap();
        assert_eq!(pi, expected_pi);
    }

    #[test]
    fn test_verify_p256_sha256_tai_1() {
        let mut ecvrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();
        let y = hex::decode("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6")
            .unwrap();
        let pi = hex::decode("029bdca4cc39e57d97e2f42f88bcf0ecb1120fb67eb408a856050dbfbcbf57c524193b7a850195ef3d5329018a8683114cb446c33fe16ebcc0bc775b043b5860dcb2e553d91268281688438df9394103ab").unwrap();
        let alpha = hex::decode("73616d706c65").unwrap();
        let expected_beta =
            hex::decode("59ca3801ad3e981a88e36880a3aee1df38a0472d5be52d6e39663ea0314e594c")
                .unwrap();
        assert_eq!(ecvrf.verify(&y, &pi, &alpha).unwrap(), expected_beta);
    }

    #[test]
    fn test_prove_p256_sha256_tai_2() {
        let mut ecvrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();
        // Secret Key (labelled as x)
        let x = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
            .unwrap();
        // Data to be hashed: ASCII "sample
        let alpha = hex::decode("74657374").unwrap();
        let expected_pi = hex::decode("03873a1cce2ca197e466cc116bca7b1156fff599be67ea40b17256c4f34ba2549c9c8b100049e76661dbcf6393e4d625597ed21d4de684e08dc6817b60938f3ff4148823ea46a47fa8a4d43f5fa6f77dc8").unwrap();
        let pi = ecvrf.prove(&x, &alpha).unwrap();
        assert_eq!(pi, expected_pi);
    }

    #[test]
    fn test_verify_p256_sha256_tai_2() {
        let mut ecvrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();
        let y = hex::decode("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6")
            .unwrap();
        let pi = hex::decode("03873a1cce2ca197e466cc116bca7b1156fff599be67ea40b17256c4f34ba2549c9c8b100049e76661dbcf6393e4d625597ed21d4de684e08dc6817b60938f3ff4148823ea46a47fa8a4d43f5fa6f77dc8").unwrap();
        let alpha = hex::decode("74657374").unwrap();
        let expected_beta =
            hex::decode("dc85c20f95100626eddc90173ab58d5e4f837bb047fb2f72e9a408feae5bc6c1")
                .unwrap();
        assert_eq!(ecvrf.verify(&y, &pi, &alpha).unwrap(), expected_beta);
    }

    #[test]
    fn test_prove_p256_sha256_tai_3() {
        let mut ecvrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();
        // Secret Key (labelled as x)
        let x = hex::decode("2ca1411a41b17b24cc8c3b089cfd033f1920202a6c0de8abb97df1498d50d2c8")
            .unwrap();
        // Data to be hashed: ASCII "sample
        let alpha = hex::decode("4578616d706c65206f66204543445341207769746820616e736970323536723120616e64205348412d323536").unwrap();
        let expected_pi = hex::decode("02abe3ce3b3aa2ab3c6855a7e729517ebfab6901c2fd228f6fa066f15ebc9b9d41fd212750d9ff775527943049053a77252e9fa59e332a2e5d5db6d0be734076e98befcdefdcbaf817a5c13d4e45fbf9bc").unwrap();
        let pi = ecvrf.prove(&x, &alpha).unwrap();
        assert_eq!(pi, expected_pi);
    }

    #[test]
    fn test_verify_p256_sha256_tai_3() {
        let mut ecvrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();
        let y = hex::decode("03596375e6ce57e0f20294fc46bdfcfd19a39f8161b58695b3ec5b3d16427c274d")
            .unwrap();
        let pi = hex::decode("02abe3ce3b3aa2ab3c6855a7e729517ebfab6901c2fd228f6fa066f15ebc9b9d41fd212750d9ff775527943049053a77252e9fa59e332a2e5d5db6d0be734076e98befcdefdcbaf817a5c13d4e45fbf9bc").unwrap();
        let alpha = hex::decode("4578616d706c65206f66204543445341207769746820616e736970323536723120616e64205348412d323536").unwrap();
        let expected_beta =
            hex::decode("e880bde34ac5263b2ce5c04626870be2cbff1edcdadabd7d4cb7cbc696467168")
                .unwrap();
        assert_eq!(ecvrf.verify(&y, &pi, &alpha).unwrap(), expected_beta);
    }

    #[test]
    fn test_derive_public_key() {
        let k = [0x01];
        let mut ctx = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();

        let secret_key = BigNum::from_slice(&k).unwrap();
        let expected = [
            0x03, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63,
            0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39,
            0x45, 0xD8, 0x98, 0xC2, 0x96,
        ];
        let derived_public_key = ctx.derive_public_key(&secret_key).unwrap();
        let expected_point = EcPoint::from_bytes(&ctx.group, &expected, &mut ctx.bn_ctx).unwrap();
        assert!(derived_public_key
            .eq(&ctx.group, &expected_point, &mut ctx.bn_ctx)
            .unwrap());
    }

    /// Hash to try and increment (TAI) test
    /// Test vector extracted from VRF RFC draft (section A.1)
    #[test]
    fn test_hash_to_try_and_increment_1() {
        let mut vrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();
        let public_key_hex =
            hex::decode("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6")
                .unwrap();
        let public_key = EcPoint::from_bytes(&vrf.group, &public_key_hex, &mut vrf.bn_ctx).unwrap();
        let expected_hash_hex =
            hex::decode("02e2e1ab1b9f5a8a68fa4aad597e7493095648d3473b213bba120fe42d1a595f3e")
                .unwrap();
        let expected_hash =
            EcPoint::from_bytes(&vrf.group, &expected_hash_hex, &mut vrf.bn_ctx).unwrap();
        // Data to be hashed: ASCII "sample
        let data = hex::decode("73616d706c65").unwrap();
        let derived_hash = vrf.hash_to_try_and_increment(&public_key, &data).unwrap();
        assert!(derived_hash
            .eq(&vrf.group, &expected_hash, &mut vrf.bn_ctx)
            .unwrap());
    }

    #[test]
    fn test_hash_to_try_and_increment_2() {
        // Example of using a different hashing function
        let mut vrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();
        let public_key_hex =
            hex::decode("03596375e6ce57e0f20294fc46bdfcfd19a39f8161b58695b3ec5b3d16427c274d")
                .unwrap();
        let public_key = EcPoint::from_bytes(&vrf.group, &public_key_hex, &mut vrf.bn_ctx).unwrap();
        let expected_hash_hex =
            hex::decode("02141e41d4d55802b0e3adaba114c81137d95fd3869b6b385d4487b1130126648d")
                .unwrap();
        let expected_hash =
            EcPoint::from_bytes(&vrf.group, &expected_hash_hex, &mut vrf.bn_ctx).unwrap();
        let data = hex::decode("4578616d706c65206f66204543445341207769746820616e736970323536723120616e64205348412d323536").unwrap();
        let derived_hash = vrf.hash_to_try_and_increment(&public_key, &data).unwrap();
        assert!(derived_hash
            .eq(&vrf.group, &expected_hash, &mut vrf.bn_ctx)
            .unwrap());
    }

    /// Nonce generation test using the curve K-163
    /// Test vector extracted from RFC6979 (section A.1)
    #[test]
    fn test_generate_nonce_k163() {
        let mut vrf = ECVRF::from_suite(CipherSuite::K163_SHA256_TAI).unwrap();
        let mut ord = BigNum::new().unwrap();
        vrf.group.order(&mut ord, &mut vrf.bn_ctx).unwrap();

        // Expected result/nonce (labelled as K or T)
        // This is the va;ue of T
        let expected_nonce = hex::decode("023AF4074C90A02B3FE61D286D5C87F425E6BDD81B").unwrap();

        // Secret Key (labelled as x)
        let sk = hex::decode("009A4D6792295A7F730FC3F2B49CBC0F62E862272F").unwrap();
        let sk_bn = BigNum::from_slice(&sk).unwrap();

        // Hashed input message (labelled as h1)
        let data = hex::decode("AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF")
            .unwrap();

        // Nonce generation
        let derived_nonce = vrf.generate_nonce(&sk_bn, &data).unwrap();

        assert_eq!(derived_nonce.to_vec(), expected_nonce);
    }

    #[test]
    fn test_generate_nonce_p256_1() {
        let mut vrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();
        let mut a = BigNum::new().unwrap();
        let mut b = BigNum::new().unwrap();
        let mut p = BigNum::new().unwrap();
        vrf.group
            .components_gfp(&mut a, &mut b, &mut p, &mut vrf.bn_ctx)
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

        // Nonce generation
        let derived_nonce = vrf.generate_nonce(&sk_bn, &data).unwrap();
        assert_eq!(derived_nonce.to_vec(), expected_nonce);
    }

    #[test]
    fn test_generate_nonce_p256_2() {
        let mut vrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();
        let mut ord = BigNum::new().unwrap();
        vrf.group.order(&mut ord, &mut vrf.bn_ctx).unwrap();
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

        // Nonce generation
        let derived_nonce = vrf.generate_nonce(&sk_bn, &data).unwrap();
        assert_eq!(derived_nonce.to_vec(), expected_nonce);
    }

    #[test]
    fn test_generate_nonce_p256_3() {
        let mut vrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();
        let mut ord = BigNum::new().unwrap();
        vrf.group.order(&mut ord, &mut vrf.bn_ctx).unwrap();
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

        // Nonce generation
        let derived_nonce = vrf.generate_nonce(&sk_bn, &data).unwrap();

        assert_eq!(derived_nonce.to_vec(), expected_nonce);
    }

    #[test]
    fn test_hash_points() {
        let mut vrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();

        let hash_hex =
            hex::decode("02e2e1ab1b9f5a8a68fa4aad597e7493095648d3473b213bba120fe42d1a595f3e")
                .unwrap();
        let hash_point = EcPoint::from_bytes(&vrf.group, &hash_hex, &mut vrf.bn_ctx).unwrap();

        let pi_hex = hex::decode("029bdca4cc39e57d97e2f42f88bcf0ecb1120fb67eb408a856050dbfbcbf57c524193b7a850195ef3d5329018a8683114cb446c33fe16ebcc0bc775b043b5860dcb2e553d91268281688438df9394103ab")
            .unwrap();

        let mut gamma_hex = pi_hex.clone();
        let c_s_hex = gamma_hex.split_off(33);
        let gamma_point = EcPoint::from_bytes(&vrf.group, &gamma_hex, &mut vrf.bn_ctx).unwrap();

        let mut c_hex = c_s_hex.clone();
        c_hex.split_off(16);

        let u_hex =
            hex::decode("02007fe22a3ed063db835a63a92cb1e487c4fea264c3f3700ae105f8f3d3fd391f")
                .unwrap();
        let u_point = EcPoint::from_bytes(&vrf.group, &u_hex, &mut vrf.bn_ctx).unwrap();

        let v_hex =
            hex::decode("03d0a63fa7a7fefcc590cb997b21bbd21dc01304102df183fb7115adf6bcbc2a74")
                .unwrap();
        let v_point = EcPoint::from_bytes(&vrf.group, &v_hex, &mut vrf.bn_ctx).unwrap();

        let computed_c = vrf
            .hash_points(&[&hash_point, &gamma_point, &u_point, &v_point])
            .unwrap();

        assert_eq!(computed_c.to_vec(), c_hex);
    }

    #[test]
    fn test_decode_proof() {
        let mut ecvrf = ECVRF::from_suite(CipherSuite::P256_SHA256_TAI).unwrap();

        let pi_hex = hex::decode("029bdca4cc39e57d97e2f42f88bcf0ecb1120fb67eb408a856050dbfbcbf57c524193b7a850195ef3d5329018a8683114cb446c33fe16ebcc0bc775b043b5860dcb2e553d91268281688438df9394103ab")
            .unwrap();
        let (derived_gamma, derived_c, _) = ecvrf.decode_proof(&pi_hex).unwrap();

        let mut gamma_hex = pi_hex.clone();
        let c_s_hex = gamma_hex.split_off(33);

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let mut bn_ctx = BigNumContext::new().unwrap();
        let gamma_point = EcPoint::from_bytes(&group, &gamma_hex, &mut bn_ctx).unwrap();

        let mut c_hex = c_s_hex.clone();
        c_hex.split_off(16);
        let c = BigNum::from_slice(c_hex.as_slice()).unwrap();

        assert!(derived_c.eq(&c));
        assert!(gamma_point.eq(&group, &derived_gamma, &mut bn_ctx).unwrap());
    }
}
