# vrf-rs
[![](https://img.shields.io/crates/v/vrf.svg)](https://crates.io/crates/vrf) [![](https://docs.rs/vrf/badge.svg)](https://docs.rs/vrf) [![](https://github.com/witnet/vrf-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/witnet/vrf-rs/actions/workflows/rust.yml)

`vrf-rs` is an open source implementation of Verifiable Random Functions (VRFs) written in Rust.

_DISCLAIMER: This is experimental software. Be careful!_

The library can be built using `cargo` and the examples can be executed with:

```bash
cargo build
cargo run --example <example_name>
```

## Elliptic Curve VRF

This module uses the OpenSSL library to offer Elliptic Curve Verifiable Random Function (VRF) functionality.

It follows the algorithms described in:

* [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
* [RFC6979](https://tools.ietf.org/html/rfc6979)

Currently the supported cipher suites are:

* `P256_SHA256_TAI`: the aforementioned algorithms with `SHA256` and the `secp256r1` curve (aka `NIST P-256`).
* `K163_SHA256_TAI`: the aforementioned algorithms with `SHA256` and the `sect163k1` curve (aka `NIST K-163`).
* `SECP256K1_SHA256_TAI`: the aforementioned algorithms with `SHA256` and the `secp256k1` curve.

### Example

Create and verify a VRF proof by using the cipher suite `SECP256K1_SHA256_TAI`:

```rust
use vrf::openssl::{CipherSuite, ECVRF};
use vrf::VRF;

fn main() {
    // Initialization of VRF context by providing a curve
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    // Inputs: Secret Key, Public Key (derived) & Message
    let secret_key =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let public_key = vrf.derive_public_key(&secret_key).unwrap();
    let message: &[u8] = b"sample";
    
    // VRF proof and hash output
    let pi = vrf.prove(&secret_key, &message).unwrap();
    let hash = vrf.proof_to_hash(&pi).unwrap();

    // VRF proof verification (returns VRF hash output)
    let beta = vrf.verify(&public_key, &pi, &message);
}
```

A complete example can be found in [examples/basic.rs](https://github.com/witnet/vrf-rs/blob/master/examples/basic.rs). It can be executed with:

```bash
cargo run --example basic
```

## Adding unsupported cipher suites

This library defines a `VRF` trait which can be extended in order to use different curves and algorithms.

```rust
pub trait VRF<PublicKey, SecretKey> {
    type Error;

    fn prove(&mut self, x: SecretKey, alpha: &[u8]) -> Result<Vec<u8>, Self::Error>;

    fn verify(&mut self, y: PublicKey, pi: &[u8], alpha: &[u8]) -> Result<Vec<u8>, Self::Error>;
}
```

## License

`vrf-rs` is published under the [MIT license][license].

[license]: https://github.com/witnet/vrf-rs/blob/master/LICENSE