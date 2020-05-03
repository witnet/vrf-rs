//! # Basic example
//!
//! This example shows a basic usage of the `vrf-rs` crate:
//!
//! 1. Instantiate the `ECVRF` by specifying the `CipherSuite`
//! 2. Generate a VRF proof by using the `prove()` function
//! 3. (Optional) Convert the VRF proof to a hash (e.g. to be used as pseudo-random value)
//! 4. Verify a VRF proof by using `verify()` function

use vrf::openssl::{CipherSuite, ECVRF};
use vrf::VRF;
use hex;

#[macro_use]
extern crate clap;

macro_rules! gen_validator {
    ($name:ident : $type:ty) => {
        gen_validator!($name, str::parse::<$type>);
    };
    ($name:ident, $expr:expr) => {
        fn $name(obj: String) -> Result<(), String> {
            $expr(&obj).map(drop).map_err(|x| format!("{}", x))
        }
    };
}
gen_validator!(is_hex_ok, hex::decode);

fn main() {

    let matches = clap_app!(vrf =>
        (version: crate_version!())
        (author: "Vixify Network")
        (about: "CLI to Verifiable Random Functions")
        (@arg VERBOSE: -v --verbose "Log verbosely to stderr.  This command does not currently log anything, so this option currently has no affect.")
        (@arg SECRET_KEY: +required {is_hex_ok} "Secret key to be used." )
        (@arg MESSAGE: +required "Message to be used." )
        //(@arg PROOF: +required {is_hex_ok} "VRF Proof to be validated." )
    )
    .get_matches();


    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    // Inputs: Secret Key, Public Key (derived) & Message
    let secret_key = hex::decode(&matches.value_of("SECRET_KEY").unwrap()).unwrap();
    //let secret_key =
    //    hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let public_key = vrf.derive_public_key(&secret_key).unwrap();
    //let message: &[u8] = b"sample";
    let message = &matches.value_of("MESSAGE").unwrap().as_bytes();

    // VRF proof and hash output
    let pi = vrf.prove(&secret_key, &message).unwrap();
    let hash = vrf.proof_to_hash(&pi).unwrap();
    println!("{}", hex::encode(&pi));

    let beta = vrf.verify(&public_key, &pi, &message);
    //let beta = hex::decode(&matches.value_of("PROOF").unwrap()).unwrap();

/*    
    let beta :[i8];
    // VRF proof verification (returns VRF hash output)
    if &matches.value_of("PROOF").unwrap() == None {
        beta = vrf.verify(&public_key, &pi, &message);
    } else {
        beta = hex::decode(&matches.value_of("PROOF").unwrap()).unwrap();
    }

    if hash == beta {
        println!("VRF proof is valid!\nHash output: {}", hex::encode(&beta));
        assert_eq!(hash, beta);
    } else {
        println!("VRF proof is not valid: proof ={},  expectd = {}", hex::encode(&beta), hex::encode(&hash));
    }
*/
    match beta {
        Ok(beta) => {
            //println!("VRF proof is valid!\nHash output: {}", hex::encode(&beta));
            assert_eq!(hash, beta);
        }
        Err(_e) => {
            //println!("VRF proof is not valid: {}", e);
        }
    }


}
