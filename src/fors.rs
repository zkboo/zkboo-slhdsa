// SPDX-License-Identifier: LGPL-3.0-or-later

//! FORS few-time signatures (FIPS 205, §8).
//!
//! Only signature verification is needed: [fors_pk_from_sig] recomputes the FORS public key from
//! a signature and the (secret) message-digest indices, using masked conditional swaps for the
//! authentication-path directions so the work done is index-independent.

use crate::{
    address::{ADRS_FORS_ROOTS, Adrs},
    hashes::{Node, f, h, t_l},
    params::N,
    util::{bit_of_u32, cond_swap_nodes, mask_from_bit, node_from_slice},
};
use alloc::vec::Vec;
use zkboo::backend::{Backend, WordRef};

/// Recomputes a FORS public key from a signature and the `k` (secret) `a`-bit tree indices
/// (FIPS 205, Algorithm 17), with index-independent control flow.
///
/// `sig_fors` is the flat FORS signature: `k` blocks of one secret-value node plus `a`
/// authentication nodes. `adrs` must have type `FORS_TREE` with layer, tree, and key-pair
/// addresses set.
pub fn fors_pk_from_sig<B: Backend>(
    sig_fors: &[WordRef<B, u8>],
    indices: &[WordRef<B, u32>],
    pk_seed: &Node<B>,
    adrs: &Adrs<B>,
    k: usize,
    a: usize,
) -> Node<B> {
    assert_eq!(
        sig_fors.len(),
        k * (a + 1) * N,
        "FORS signature must be k·(a+1)·n bytes"
    );
    assert_eq!(indices.len(), k, "one index per FORS tree");
    let mut tree_adrs = adrs.clone();
    let mut roots: Vec<WordRef<B, u8>> = Vec::with_capacity(k * N);
    for i in 0..k {
        let base = i * (a + 1) * N;
        let sk = node_from_slice(&sig_fors[base..base + N]);
        // Leaf index within the whole FORS forest: i·2^a + indices[i] (disjoint bits, so XOR).
        let leaf_idx = indices[i].clone() ^ ((i as u32) << a);
        tree_adrs.set_tree_height_const(0);
        tree_adrs.set_tree_index_wire(&leaf_idx);
        let mut node = f(&tree_adrs, pk_seed, &sk);
        for j in 0..a {
            tree_adrs.set_tree_height_const((j + 1) as u32);
            tree_adrs.set_tree_index_wire(&(leaf_idx.clone() >> (j + 1)));
            let auth = node_from_slice(&sig_fors[base + (1 + j) * N..base + (2 + j) * N]);
            // Bit j of the tree index picks the side: 0 hashes node ‖ auth, 1 hashes auth ‖ node.
            let mask = mask_from_bit(bit_of_u32(&indices[i], j));
            let (l, r) = cond_swap_nodes(&mask, &node, &auth);
            node = h(&tree_adrs, pk_seed, &l, &r);
        }
        roots.extend(node);
    }
    let mut roots_adrs = adrs.clone();
    roots_adrs.set_type_and_clear(ADRS_FORS_ROOTS);
    roots_adrs.copy_key_pair_from(adrs);
    return t_l(&roots_adrs, pk_seed, roots);
}
