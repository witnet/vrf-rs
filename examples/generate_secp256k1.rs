//! # Generate `Secp256k1` VRF test vectors
//!
//! This example generates VRF proofs (using the ciphersuite `SECP256K1_SHA256_TAI`)
//! and writes them into a JSON file (`vrf.json`).
//!
//! The input data (in `secp256k1.json` file) is extracted from the
//! [Chuck Batson Secp256k1 test vectors](https://chuckbatson.wordpress.com/2014/11/26/secp256k1-test-vectors/).
//!
//! This example expects uses a file with a JSON array with objects with the following keys:
//!
//!  - `k`: private key
//!  - `x`: coordinate `x` of public key
//!  - `y`: coordinate `y` of public key
//!
//! This example outputs a JSON file with test vectors with the following keys:
//!
//!  - `priv`: private key
//!  - `pub`: compressed public key
//!  - `message`: message used for VRF
//!  - `pi`: computed VRF proof

use std::fs::File;
use std::io::{BufWriter, Write};

use openssl::bn::BigNum;
use serde_json::{json, Value};

use vrf::openssl::{CipherSuite, ECVRF};
use vrf::VRF;

fn to_hex_string(bytes: Vec<u8>) -> String {
    bytes
        .iter()
        .fold(String::from("0x"), |acc, x| format!("{}{:02x}", acc, x))
}

fn main() {
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).expect("VRF should init");

    // VRF inputs extracted from `Secp256k1` test vectors + `sample` message
    let file = File::open("./examples/secp256k1.json").expect("File should open read only");
    let json: Value = serde_json::from_reader(file).expect("File should be proper JSON");
    let inputs = json.as_array().expect("File should have priv key");
    let message: &[u8] = b"sample";

    // VRF outputs
    let outputs: Vec<Value> = inputs
        .iter()
        .map(|val| {
            // Private key as input
            let secret_key_str = val.get("k").unwrap().as_str().unwrap();
            let secret_key = BigNum::from_dec_str(secret_key_str).unwrap().to_vec();
            // Derive public key
            let public_key = vrf.derive_public_key(&secret_key).unwrap();
            // VRF proof
            let pi = vrf.prove(&secret_key, &message).unwrap();
            // VRF proof to hash
            let hash = vrf.proof_to_hash(&pi).unwrap();

            json!({
                "priv": val.get("k"),
                "pub": to_hex_string(public_key),
                "message": to_hex_string(message.to_vec()),
                "pi": to_hex_string(pi),
                "hash": to_hex_string(hash)
            })
        })
        .collect();

    // Write results into file `vrf.json`
    let f = File::create("./vrf.json").expect("Unable to create file");
    serde_json::to_writer_pretty(BufWriter::new(f).by_ref(), &json!(outputs)).unwrap();
}
