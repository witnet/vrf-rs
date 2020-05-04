//! # Client example
//!
//! This example shows a command line client usage of the `vrf-rs` crate:
//!
//! 1. Instantiate the `ECVRF` by specifying the `CipherSuite`
//! 2. Generate a VRF proof by using the `prove()` function
//! 3. (Optional) Convert the VRF proof to a hash (e.g. to be used as pseudo-random value)
//! 4. Verify a VRF proof by using `verify()` function

use hex;
use vrf::openssl::{CipherSuite, ECVRF};
use vrf::VRF;

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
        (about: "Client to Verifiable Random Functions")
        (@arg VERBOSE: -v --verbose "Log verbosely to stderr.  This command does not currently log anything, so this option currently has no affect.")
        (@arg SECRET_KEY: +required {is_hex_ok} "Secret key to be used to print or validate proof" )
        (@arg MESSAGE: +required "Message to be used to print or validate proof." )
        (@arg PROOF: {is_hex_ok} "Optional VRF Proof to be validated. If missing, proof is printed for secret and message." )
    )
    .get_matches();

    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    // Inputs: Secret Key, Public Key (derived) & Message
    let secret_key = hex::decode(&matches.value_of("SECRET_KEY").unwrap()).unwrap();
    let public_key = vrf.derive_public_key(&secret_key).unwrap();
    let message = &matches.value_of("MESSAGE").unwrap().as_bytes();

    let mut pi = vrf.prove(&secret_key, &message).unwrap();
    let hash = vrf.proof_to_hash(&pi).unwrap();

    // VRF proof and hash output
    let proof_given = matches.value_of("PROOF") != None;
    if proof_given {
        pi = hex::decode(&matches.value_of("PROOF").unwrap()).unwrap();
    } else {
        println!("{}", hex::encode(&pi));
    }

    let beta = vrf.verify(&public_key, &pi, &message);

    if proof_given {
        match beta {
            Ok(beta) => {
                println!("VRF proof is valid!");
                assert_eq!(hash, beta);
            }
            Err(_e) => {
                println!("VRF proof is not valid!");
            }
        }
    }
}
