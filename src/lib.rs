// SPDX-License-Identifier: LGPL-3.0-or-later

//! SLH-DSA (SPHINCS+, FIPS 205) as [zkboo] circuits, for the SLH-DSA-SHAKE-128s and
//! SLH-DSA-SHAKE-128f parameter sets.
//!
//! Two operations are provided as circuit functions:
//!
//! - [slh_keygen_root]: recomputes the public-key root from the secret seed `SK.seed`,
//!   proving in zero knowledge that a public key derives from a secret seed;
//! - [slh_verify_root]: recomputes the public-key root from a message and a signature,
//!   proving in zero knowledge that a valid signature for the message is known
//!   (the signature being the secret witness) without revealing it.
//!
//! Both return the recomputed `PK.root` as circuit wires: a consumer outputs those wires and the
//! proof verifier checks them against the known public key, so no in-circuit comparison is needed.
//!
//! Signing is deliberately out of scope: it is orders of magnitude more expensive than
//! verification and has no clear zero-knowledge use case.
//!
//! See FIPS 205 <https://doi.org/10.6028/NIST.FIPS.205>.

#![no_std]
extern crate alloc;

pub mod address;
pub mod fors;
pub mod hashes;
pub mod params;
pub mod slh;
pub mod util;
pub mod wots;
pub mod xmss;

pub use hashes::Node;
pub use params::{N, SLH_DSA_SHAKE_128F, SLH_DSA_SHAKE_128S, SlhDsaParams};
pub use slh::{slh_keygen_root, slh_verify_root};
