// SPDX-License-Identifier: LGPL-3.0-or-later

//! The top-level SLH-DSA circuits: key generation and signature verification (FIPS 205, §9–10).

use crate::{
    address::{ADRS_FORS_TREE, Adrs},
    fors::fors_pk_from_sig,
    hashes::{Node, h_msg},
    params::{N, SlhDsaParams},
    util::base_2b_u32,
    wots::LEN,
    xmss::{xmss_pk_from_sig, xmss_root},
};
use alloc::vec::Vec;
use core::array;
use zkboo::backend::{Allocator, Backend, WordRef};

/// Recomputes the SLH-DSA public-key root `PK.root` from the secret seed `SK.seed` (FIPS 205,
/// Algorithm 18, root computation).
pub fn slh_keygen_root<B: Backend>(
    allocator: Allocator<B>,
    sk_seed: Node<B>,
    pk_seed: &[u8; N],
    params: &SlhDsaParams,
) -> Node<B> {
    let pk_seed: Node<B> = array::from_fn(|i| allocator.alloc(pk_seed[i]));
    let mut adrs = Adrs::new(allocator);
    adrs.set_layer((params.d - 1) as u32);
    return xmss_root(&sk_seed, &pk_seed, &adrs, params.h_prime);
}

/// Recomputes the SLH-DSA public-key root `PK.root` from a message and a signature (FIPS 205,
/// Algorithm 20), with signature-independent control flow.
pub fn slh_verify_root<B: Backend>(
    allocator: Allocator<B>,
    msg: Vec<WordRef<B, u8>>,
    sig: Vec<WordRef<B, u8>>,
    pk_seed: &[u8; N],
    pk_root: &[u8; N],
    params: &SlhDsaParams,
) -> Node<B> {
    assert_eq!(
        sig.len(),
        params.sig_len(),
        "signature must be exactly sig_len bytes"
    );
    let pk_seed: Node<B> = array::from_fn(|i| allocator.alloc(pk_seed[i]));
    let pk_root: Node<B> = array::from_fn(|i| allocator.alloc(pk_root[i]));
    // Split the signature: randomizer R, FORS signature, hypertree signature.
    let r: Node<B> = array::from_fn(|i| sig[i].clone());
    let fors_len = params.k * (params.a + 1) * N;
    let sig_fors = &sig[N..N + fors_len];
    let sig_ht = &sig[N + fors_len..];
    // Compute and parse the message digest: k a-bit FORS indices, then the hypertree index
    // (h − h' bits) and the leaf index (h' bits) as masked big-endian integers.
    let digest = h_msg(allocator.clone(), &r, &pk_seed, &pk_root, msg, params.m);
    let md_len = (params.k * params.a).div_ceil(8);
    let tree_bits = params.h - params.h_prime;
    let tree_len = tree_bits.div_ceil(8);
    let leaf_len = params.h_prime.div_ceil(8);
    assert_eq!(md_len + tree_len + leaf_len, params.m, "digest layout");
    let indices = base_2b_u32(&allocator, &digest[..md_len], params.a, params.k);
    let zero = allocator.alloc(0u8);
    let tree_bytes: Vec<WordRef<B, u8>> = (0..8)
        .map(|i| match (i + tree_len).checked_sub(8) {
            Some(j) => digest[md_len + j].clone(),
            None => zero.clone(),
        })
        .collect();
    let idx_tree = WordRef::<B, u64>::from_be_bytes(tree_bytes)
        .ok()
        .expect("8 tree-index bytes");
    let idx_tree = (idx_tree << (64 - tree_bits)) >> (64 - tree_bits);
    let leaf_bytes: Vec<WordRef<B, u8>> = (0..4)
        .map(|i| match (i + leaf_len).checked_sub(4) {
            Some(j) => digest[md_len + tree_len + j].clone(),
            None => zero.clone(),
        })
        .collect();
    let idx_leaf = WordRef::<B, u32>::from_be_bytes(leaf_bytes)
        .ok()
        .expect("4 leaf-index bytes");
    let idx_leaf = (idx_leaf << (32 - params.h_prime)) >> (32 - params.h_prime);
    // Recompute the FORS public key.
    let mut fors_adrs = Adrs::new(allocator.clone());
    fors_adrs.set_tree_addr_wire(&idx_tree);
    fors_adrs.set_type_and_clear(ADRS_FORS_TREE);
    fors_adrs.set_key_pair_wire(&idx_leaf);
    let mut node = fors_pk_from_sig(sig_fors, &indices, &pk_seed, &fors_adrs, params.k, params.a);
    // Walk the hypertree: layer j sits in the tree indexed by the high bits of idx_tree, at the
    // leaf given by the next h' bits (layer 0 uses idx_leaf from the digest directly).
    let xmss_len = (LEN + params.h_prime) * N;
    for j in 0..params.d {
        let (layer_tree, layer_leaf) = if j == 0 {
            (idx_tree.clone(), idx_leaf.clone())
        } else {
            let shifted = idx_tree.clone() >> ((j - 1) * params.h_prime);
            let leaf = (shifted.clone() << (64 - params.h_prime)) >> (64 - params.h_prime);
            (shifted >> params.h_prime, leaf.cast::<u32>())
        };
        let mut layer_adrs = Adrs::new(allocator.clone());
        layer_adrs.set_layer(j as u32);
        layer_adrs.set_tree_addr_wire(&layer_tree);
        node = xmss_pk_from_sig(
            &layer_leaf,
            &sig_ht[j * xmss_len..(j + 1) * xmss_len],
            &node,
            &pk_seed,
            &layer_adrs,
            params.h_prime,
        );
    }
    return node;
}
