pub mod dummy;
pub mod openssl;

/// A trait for a Verifiable Random Functions (VRF) implementations.
pub trait VRF<PublicKey, SecretKey> {
    type Error;

    /// Generates proof from a secret key and message
    ///
    /// # Arguments
    ///
    /// * `x`     - A secret key
    /// * `alpha` - A slice representing the message in octets
    ///
    /// # Returns
    ///
    /// * If successful, a vector of octets representing the proof of the VRF
    fn prove(&mut self, x: SecretKey, alpha: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Verifies the provided VRF proof and computes the VRF hash output
    ///
    /// # Arguments
    ///
    /// * `y`   - A public key
    /// * `pi`  - A slice of octets representing the VRF proof
    ///
    /// # Returns
    ///
    /// * If successful, a vector of octets with the VRF hash output
    fn verify(&mut self, y: PublicKey, pi: &[u8], alpha: &[u8]) -> Result<Vec<u8>, Self::Error>;
}
