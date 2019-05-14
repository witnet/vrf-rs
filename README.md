# vrf-rs
[![](https://img.shields.io/crates/v/vrf.svg)](https://crates.io/crates/vrf) [![](https://docs.rs/vrf/badge.svg)](https://docs.rs/vrf) [![](https://travis-ci.com/witnet/vrf-rs.svg?branch=master)](https://travis-ci.com/witnet/vrf-rs)

`vrf-rs` is an open source implementation of Verifiable Random Functions (VRFs) written in Rust.

_DISCLAIMER: This is experimental software. Be careful!_

## Elliptic Curve VRF

This module uses the OpenSSL library to offer Elliptic Curve Verifiable Random Function (VRF) functionality.

It follows the algorithms described in:

* [VRF-draft-04](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-04)
* [RFC6979](https://tools.ietf.org/html/rfc6979)

Currently the supported cipher suites are:

* `P256_SHA256_TAI`: the aforementioned algorithms with `SHA256` and the `NIST P-256` curve.
* `K163_SHA256_TAI`: the aforementioned algorithms with `SHA256` and the `NIST K-163` curve.
* `SECP256K1_SHA256_TAI`: the aforementioned algorithms with `SHA256` and the `secp256k1` curve.

### Example

Create and verify a VRF proof by using the cipher suite `SECP256K1_SHA256_TAI`:

```rust
    use vrf::VRF;
    use vrf::openssl::{CipherSuite, ECVRF};

    // Initialization of VRF context by providing a curve
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI)?;
    
    // `prove` returns a `Result` with the VRF proof as `Vec<u8>`
    let proof = vrf.prove(&secret_key, &message)?;
    
    // `verify` returns a `Result` with the VRF hash output as `Vec<u8>`
    let proof_hash = vrf.verify(&public_key, &pi, &message);
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

vrf-rs is published under the [GNU General Public License v3.0][license].

[license]: https://github.com/witnet/vrf-rs/blob/master/LICENSE