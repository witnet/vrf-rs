//! # Verifiable Random Function (VRF)
//!
//! This crate defines the generic contract that must be followed by VRF implementations ([`VRF`](trait.VRF.html) trait).
//!
//! ## Elliptic Curve VRF
//!
//! The [`openssl`](openssl/index.html) module provides an implementation of Elliptic Curve VRF ([`ECVRF`](openssl/struct.ECVRF.html)).
//!
//! It follows the algorithms described in:
//!
//! * [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
//! * [RFC6979](https://tools.ietf.org/html/rfc6979)
//!
//! Currently the supported cipher suites are:
//!
//! * `P256_SHA256_TAI`: the aforementioned algorithms with `SHA256` and the `NIST P-256` curve.
//! * `K163_SHA256_TAI`: the aforementioned algorithms with `SHA256` and the `NIST K-163` curve.
//! * `SECP256K1_SHA256_TAI`: the aforementioned algorithms with `SHA256` and the `secp256k1` curve.
pub mod dummy;
pub mod openssl;

/// A trait containing the common capabilities for all Verifiable Random Functions (VRF) implementations.
pub trait VRF<PublicKey, SecretKey> {
    type Error;

    /// Generates proof from a secret key and a message.
    ///
    /// # Arguments
    ///
    /// * `x`     - A secret key.
    /// * `alpha` - A slice representing the message in octets.
    ///
    /// # Returns
    ///
    /// * If successful, a vector of octets representing the proof of the VRF.
    fn prove(&mut self, x: SecretKey, alpha: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Verifies the provided VRF proof and computes the VRF hash output.
    ///
    /// # Arguments
    ///
    /// * `y`   - A public key.
    /// * `pi`  - A slice of octets representing the VRF proof.
    ///
    /// # Returns
    ///
    /// * If successful, a vector of octets with the VRF hash output.
    fn verify(&mut self, y: PublicKey, pi: &[u8], alpha: &[u8]) -> Result<Vec<u8>, Self::Error>;
}
