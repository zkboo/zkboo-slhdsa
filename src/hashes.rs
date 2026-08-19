// SPDX-License-Identifier: LGPL-3.0-or-later

//! The SLH-DSA-SHAKE hash functions (FIPS 205, §11.1).
//!
//! In the SHAKE instantiation every function is a single SHAKE256 call: the tweakable hashes
//! `F`, `H`, `T_l` and the secret-value PRF all hash `PK.seed ‖ ADRS ‖ input` to `n` bytes, and
//! `H_msg` hashes `R ‖ PK.seed ‖ PK.root ‖ M` to `m` bytes.

use crate::{address::Adrs, params::N};
use alloc::vec::Vec;
use zkboo::backend::{Allocator, Backend, WordRef};
use zkboo_keccak::shake256;

/// An `n`-byte hash value: a Merkle-tree node, chain value, seed, or public-key root.
pub type Node<B> = [WordRef<B, u8>; N];

/// The common shape of `F`, `H`, `T_l`, and `PRF`: hashes `PK.seed ‖ ADRS ‖ input` to `n` bytes.
fn thash<B: Backend>(
    adrs: &Adrs<B>,
    pk_seed: &Node<B>,
    input: impl IntoIterator<Item = WordRef<B, u8>>,
) -> Node<B> {
    let mut msg: Vec<WordRef<B, u8>> = Vec::new();
    msg.extend(pk_seed.iter().cloned());
    msg.extend(adrs.bytes().iter().cloned());
    msg.extend(input);
    return shake256(adrs.allocator(), msg, N)
        .try_into()
        .ok()
        .expect("n output bytes");
}

/// The tweakable hash `F`: hashes a single `n`-byte value.
pub fn f<B: Backend>(adrs: &Adrs<B>, pk_seed: &Node<B>, m: &Node<B>) -> Node<B> {
    return thash(adrs, pk_seed, m.iter().cloned());
}

/// The tweakable hash `H`: hashes two `n`-byte values (Merkle-tree children).
pub fn h<B: Backend>(adrs: &Adrs<B>, pk_seed: &Node<B>, l: &Node<B>, r: &Node<B>) -> Node<B> {
    return thash(adrs, pk_seed, l.iter().chain(r.iter()).cloned());
}

/// The tweakable hash `T_l`: hashes a concatenation of `n`-byte values (WOTS+ chain tops or FORS
/// roots), given as a flat byte-wire vector.
pub fn t_l<B: Backend>(adrs: &Adrs<B>, pk_seed: &Node<B>, input: Vec<WordRef<B, u8>>) -> Node<B> {
    assert!(input.len() % N == 0, "T_l input must be whole nodes");
    return thash(adrs, pk_seed, input);
}

/// The secret-value PRF: hashes `PK.seed ‖ ADRS ‖ SK.seed` to `n` bytes.
pub fn prf<B: Backend>(adrs: &Adrs<B>, pk_seed: &Node<B>, sk_seed: &Node<B>) -> Node<B> {
    return thash(adrs, pk_seed, sk_seed.iter().cloned());
}

/// The message digest `H_msg`: hashes `R ‖ PK.seed ‖ PK.root ‖ M` to `m` bytes.
pub fn h_msg<B: Backend>(
    allocator: Allocator<B>,
    r: &Node<B>,
    pk_seed: &Node<B>,
    pk_root: &Node<B>,
    msg: Vec<WordRef<B, u8>>,
    m: usize,
) -> Vec<WordRef<B, u8>> {
    let mut input: Vec<WordRef<B, u8>> = Vec::with_capacity(3 * N + msg.len());
    input.extend(r.iter().cloned());
    input.extend(pk_seed.iter().cloned());
    input.extend(pk_root.iter().cloned());
    input.extend(msg);
    return shake256(allocator, input, m);
}
