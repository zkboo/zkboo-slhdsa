// SPDX-License-Identifier: LGPL-3.0-or-later

//! SLH-DSA (SPHINCS+, FIPS 205) as [zkboo] circuits, for the security-category-1 parameter sets
//! SLH-DSA-SHAKE-128s/128f and SLH-DSA-SHA2-128s/128f.

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
pub use params::{
    HashInstantiation, N, SLH_DSA_SHA2_128F, SLH_DSA_SHA2_128S, SLH_DSA_SHAKE_128F,
    SLH_DSA_SHAKE_128S, SlhDsaParams,
};
pub use slh::{slh_keygen_root, slh_verify_root};
