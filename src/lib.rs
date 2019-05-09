pub mod dummy;
pub mod openssl;

/// A trait for a Verifiable Random Functions (VRF)
/// implementations.
pub trait VRF<PublicKey, SecretKey> {
    type Error;

    /// Generate proof from key pair and message
    fn prove(&mut self, x: SecretKey, alpha: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Verify proof given public key, proof and message
    fn verify(&mut self, y: PublicKey, pi: &[u8], alpha: &[u8]) -> Result<Vec<u8>, Self::Error>;
}
