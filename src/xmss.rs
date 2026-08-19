// SPDX-License-Identifier: LGPL-3.0-or-later

//! XMSS Merkle trees over WOTS+ leaves (FIPS 205, §6).
//!
//! [xmss_root] computes a tree root from the secret seed with public control flow, using an
//! iterative treehash (a stack of at most `h' + 1` nodes) rather than the recursive formulation
//! of FIPS 205, producing the same hash calls with the same addresses. [xmss_pk_from_sig] walks
//! an authentication path whose directions depend on the secret leaf index, using masked
//! conditional swaps so the work done is index-independent.

use crate::{
    address::{ADRS_TREE, ADRS_WOTS_HASH, Adrs},
    hashes::{Node, h},
    params::N,
    util::{bit_of_u32, cond_swap_nodes, mask_from_bit, node_from_slice},
    wots::{LEN, wots_pk_from_sig, wots_pk_gen},
};
use alloc::vec::Vec;
use zkboo::backend::{Backend, WordRef};

/// Computes the root of the XMSS tree of height `h_prime` (FIPS 205, Algorithm 9, for the full
/// tree).
///
/// `adrs` must have the layer and tree addresses set; type and remaining fields are managed here.
pub fn xmss_root<B: Backend>(
    sk_seed: &Node<B>,
    pk_seed: &Node<B>,
    adrs: &Adrs<B>,
    h_prime: usize,
) -> Node<B> {
    // Stack of (node, height, index) with strictly decreasing heights; each new leaf is merged
    // upward while the stack top has its own height.
    let mut stack: Vec<(Node<B>, usize, usize)> = Vec::with_capacity(h_prime + 1);
    for i in 0..(1usize << h_prime) {
        let mut leaf_adrs = adrs.clone();
        leaf_adrs.set_type_and_clear(ADRS_WOTS_HASH);
        leaf_adrs.set_key_pair_const(i as u32);
        let mut node = wots_pk_gen(sk_seed, pk_seed, &leaf_adrs);
        let mut height = 0usize;
        let mut index = i;
        while let Some((_, top_height, _)) = stack.last()
            && *top_height == height
        {
            let (left, _, _) = stack.pop().expect("stack top exists");
            height += 1;
            index >>= 1;
            let mut tree_adrs = adrs.clone();
            tree_adrs.set_type_and_clear(ADRS_TREE);
            tree_adrs.set_tree_height_const(height as u32);
            tree_adrs.set_tree_index_const(index as u32);
            node = h(&tree_adrs, pk_seed, &left, &node);
        }
        stack.push((node, height, index));
    }
    let (root, height, _) = stack.pop().expect("root remains");
    assert_eq!(height, h_prime, "treehash must end at the root");
    assert!(stack.is_empty(), "treehash must consume the whole stack");
    return root;
}

/// Recomputes an XMSS root from a leaf value, a signature, and the (secret) leaf index
/// (FIPS 205, Algorithm 11), with index-independent control flow.
///
/// `sig_xmss` is the flat XMSS signature: 35 WOTS+ nodes followed by `h_prime` authentication
/// nodes. `adrs` must have the layer and tree addresses set.
pub fn xmss_pk_from_sig<B: Backend>(
    idx_leaf: &WordRef<B, u32>,
    sig_xmss: &[WordRef<B, u8>],
    msg: &Node<B>,
    pk_seed: &Node<B>,
    adrs: &Adrs<B>,
    h_prime: usize,
) -> Node<B> {
    assert_eq!(
        sig_xmss.len(),
        (LEN + h_prime) * N,
        "XMSS signature must be (len + h')·n bytes"
    );
    let mut wots_adrs = adrs.clone();
    wots_adrs.set_type_and_clear(ADRS_WOTS_HASH);
    wots_adrs.set_key_pair_wire(idx_leaf);
    let mut node = wots_pk_from_sig(&sig_xmss[..LEN * N], msg, pk_seed, &wots_adrs);
    let mut tree_adrs = adrs.clone();
    tree_adrs.set_type_and_clear(ADRS_TREE);
    for k in 0..h_prime {
        tree_adrs.set_tree_height_const((k + 1) as u32);
        tree_adrs.set_tree_index_wire(&(idx_leaf.clone() >> (k + 1)));
        let auth = node_from_slice(&sig_xmss[(LEN + k) * N..(LEN + k + 1) * N]);
        // Bit k of the leaf index picks the side: 0 hashes node ‖ auth, 1 hashes auth ‖ node.
        let mask = mask_from_bit(bit_of_u32(idx_leaf, k));
        let (l, r) = cond_swap_nodes(&mask, &node, &auth);
        node = h(&tree_adrs, pk_seed, &l, &r);
    }
    return node;
}
