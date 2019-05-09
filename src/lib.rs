mod dummy;
mod p256v1;

/// A trait for a Verifiable Random Functions (VRF)
/// implementations.
pub trait VRF<PublicKey, SecretKey> {
    type Error;

    /// Generate proof from key pair and message
    fn prove(x: SecretKey, alpha: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Verify proof given public key, proof and message
    fn verify(y: PublicKey, pi: &[u8], alpha: &[u8]) -> Result<Vec<u8>, Self::Error>;
}
