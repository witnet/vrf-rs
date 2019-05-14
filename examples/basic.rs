use vrf::openssl::{CipherSuite, ECVRF};
use vrf::VRF;

fn main() {
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    // Secret Key (labelled as x)
    let secret_key =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let public_key = vrf.derive_public_key(&secret_key).unwrap();

    // Data: ASCII "sample"
    let message: &[u8] = b"sample";
    let pi = vrf.prove(&secret_key, &message).unwrap();
    println!("Generated VRF proof: {}", hex::encode(&pi));

    // Compute VRF hash ouput
    let hash = vrf.proof_to_hash(&pi).unwrap();

    // Verify VRF proof (returns VRF hash output)
    let beta = vrf.verify(&public_key, &pi, &message);

    match beta {
        Ok(beta) => {
            println!("VRF proof is valid!\nHash output: {}", hex::encode(&beta));
            assert_eq!(hash, beta);
        }
        Err(e) => {
            println!("VRF proof is not valid: {}", e);
        }
    }
}
