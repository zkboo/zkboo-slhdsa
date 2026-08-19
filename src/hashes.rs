// SPDX-License-Identifier: LGPL-3.0-or-later

//! The SLH-DSA hash functions (FIPS 205, §11), for both category-1 instantiations.
//!
//! In the SHAKE instantiation every function is a single SHAKE256 call over
//! `PK.seed ‖ ADRS ‖ input` (and `H_msg` over `R ‖ PK.seed ‖ PK.root ‖ M`).
//! In the SHA2 instantiation (category 1) every function is SHA-256: the tweakable hashes and
//! the PRF hash `PK.seed ‖ toByte(0, 64−n) ‖ ADRSc ‖ input` truncated to `n` bytes (the zero
//! padding fills the first compression block; `ADRSc` is the compressed 22-byte address), and
//! `H_msg` is `MGF1-SHA-256(R ‖ PK.seed ‖ SHA-256(R ‖ PK.seed ‖ PK.root ‖ M), m)`.

use crate::{
    address::Adrs,
    params::{HashInstantiation, N, SlhDsaParams},
};
use alloc::vec::Vec;
use zkboo::backend::{Allocator, Backend, WordRef};
use zkboo_keccak::shake256;
use zkboo_sha2::sha256bytes;

/// An `n`-byte hash value: a Merkle-tree node, chain value, seed, or public-key root.
pub type Node<B> = [WordRef<B, u8>; N];

/// The SHA-256 block size in bytes: the zero padding after `PK.seed` fills one block.
const SHA2_BLOCK: usize = 64;

/// The common shape of `F`, `H`, `T_l`, and `PRF`: hashes the seed-and-address tweak followed by
/// `input` to `n` bytes, per the parameter set's instantiation.
fn thash<B: Backend>(
    params: &SlhDsaParams,
    adrs: &Adrs<B>,
    pk_seed: &Node<B>,
    input: impl IntoIterator<Item = WordRef<B, u8>>,
) -> Node<B> {
    let allocator = adrs.allocator();
    let mut msg: Vec<WordRef<B, u8>> = Vec::new();
    msg.extend(pk_seed.iter().cloned());
    return match params.hash {
        HashInstantiation::Shake => {
            msg.extend(adrs.bytes().iter().cloned());
            msg.extend(input);
            shake256(allocator, msg, N)
                .try_into()
                .ok()
                .expect("n output bytes")
        }
        HashInstantiation::Sha2 => {
            msg.extend((N..SHA2_BLOCK).map(|_| allocator.alloc(0u8)));
            msg.extend(adrs.compressed_bytes());
            msg.extend(input);
            let digest = sha256bytes(allocator, msg);
            core::array::from_fn(|i| digest[i].clone())
        }
    };
}

/// The tweakable hash `F`: hashes a single `n`-byte value.
pub fn f<B: Backend>(
    params: &SlhDsaParams,
    adrs: &Adrs<B>,
    pk_seed: &Node<B>,
    m: &Node<B>,
) -> Node<B> {
    return thash(params, adrs, pk_seed, m.iter().cloned());
}

/// The tweakable hash `H`: hashes two `n`-byte values (Merkle-tree children).
pub fn h<B: Backend>(
    params: &SlhDsaParams,
    adrs: &Adrs<B>,
    pk_seed: &Node<B>,
    l: &Node<B>,
    r: &Node<B>,
) -> Node<B> {
    return thash(params, adrs, pk_seed, l.iter().chain(r.iter()).cloned());
}

/// The tweakable hash `T_l`: hashes a concatenation of `n`-byte values (WOTS+ chain tops or
/// FORS roots), given as a flat byte-wire vector.
pub fn t_l<B: Backend>(
    params: &SlhDsaParams,
    adrs: &Adrs<B>,
    pk_seed: &Node<B>,
    input: Vec<WordRef<B, u8>>,
) -> Node<B> {
    assert!(input.len() % N == 0, "T_l input must be whole nodes");
    return thash(params, adrs, pk_seed, input);
}

/// The secret-value PRF: hashes the seed-and-address tweak followed by `SK.seed` to `n` bytes.
pub fn prf<B: Backend>(
    params: &SlhDsaParams,
    adrs: &Adrs<B>,
    pk_seed: &Node<B>,
    sk_seed: &Node<B>,
) -> Node<B> {
    return thash(params, adrs, pk_seed, sk_seed.iter().cloned());
}

/// The message digest `H_msg`: hashes `R ‖ PK.seed ‖ PK.root ‖ M` to `m` bytes.
pub fn h_msg<B: Backend>(
    params: &SlhDsaParams,
    allocator: Allocator<B>,
    r: &Node<B>,
    pk_seed: &Node<B>,
    pk_root: &Node<B>,
    msg: Vec<WordRef<B, u8>>,
) -> Vec<WordRef<B, u8>> {
    let mut input: Vec<WordRef<B, u8>> = Vec::with_capacity(3 * N + msg.len());
    input.extend(r.iter().cloned());
    input.extend(pk_seed.iter().cloned());
    input.extend(pk_root.iter().cloned());
    input.extend(msg);
    return match params.hash {
        HashInstantiation::Shake => shake256(allocator, input, params.m),
        HashInstantiation::Sha2 => {
            let inner = sha256bytes(allocator.clone(), input);
            let mut mgf_seed: Vec<WordRef<B, u8>> = Vec::with_capacity(2 * N + 32);
            mgf_seed.extend(r.iter().cloned());
            mgf_seed.extend(pk_seed.iter().cloned());
            mgf_seed.extend(inner);
            mgf1_sha256(allocator, &mgf_seed, params.m)
        }
    };
}

/// The MGF1 mask-generation function over SHA-256 (RFC 8017, §B.2.1): concatenates
/// `SHA-256(seed ‖ toByte(counter, 4))` for `counter = 0, 1, …` and truncates to `len` bytes.
fn mgf1_sha256<B: Backend>(
    allocator: Allocator<B>,
    seed: &[WordRef<B, u8>],
    len: usize,
) -> Vec<WordRef<B, u8>> {
    let mut out: Vec<WordRef<B, u8>> = Vec::with_capacity(len);
    let mut counter = 0u32;
    while out.len() < len {
        let mut input: Vec<WordRef<B, u8>> = Vec::with_capacity(seed.len() + 4);
        input.extend(seed.iter().cloned());
        input.extend(counter.to_be_bytes().map(|b| allocator.alloc(b)));
        let block = sha256bytes(allocator.clone(), input);
        out.extend(block.into_iter().take(len - out.len()));
        counter += 1;
    }
    return out;
}
