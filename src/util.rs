// SPDX-License-Identifier: LGPL-3.0-or-later

//! In-circuit building blocks for data-independent control flow.

use crate::hashes::Node;
use alloc::vec::Vec;
use core::array;
use zkboo::backend::{Allocator, Backend, WordRef};

/// Expands a single-bit word (holding 0 or 1) into a full byte mask (0x00 or 0xFF).
pub fn mask_from_bit<B: Backend>(bit: WordRef<B, u8>) -> WordRef<B, u8> {
    return (!bit) + 1u8;
}

/// Selects between two nodes under a byte mask: `on_ones` if the mask is 0xFF, else `on_zeros`.
pub fn select_node<B: Backend>(
    mask: &WordRef<B, u8>,
    on_ones: &Node<B>,
    on_zeros: &Node<B>,
) -> Node<B> {
    return array::from_fn(|i| {
        on_zeros[i].clone() ^ (mask.clone() & (on_ones[i].clone() ^ on_zeros[i].clone()))
    });
}

/// Swaps two nodes if the byte mask is 0xFF, passes them through unchanged if it is 0x00.
pub fn cond_swap_nodes<B: Backend>(
    mask: &WordRef<B, u8>,
    l: &Node<B>,
    r: &Node<B>,
) -> (Node<B>, Node<B>) {
    let delta: Node<B> = array::from_fn(|i| mask.clone() & (l[i].clone() ^ r[i].clone()));
    return (
        array::from_fn(|i| l[i].clone() ^ delta[i].clone()),
        array::from_fn(|i| r[i].clone() ^ delta[i].clone()),
    );
}

/// Extracts bit `j` (counting from the least significant) of a u32 word, as a u8 word holding 0 or
/// 1.
pub fn bit_of_u32<B: Backend>(x: &WordRef<B, u32>, j: usize) -> WordRef<B, u8> {
    return ((x.clone() << (31 - j)) >> 31).cast();
}

/// Copies a node out of a byte-wire slice.
pub fn node_from_slice<B: Backend>(s: &[WordRef<B, u8>]) -> Node<B> {
    return array::from_fn(|i| s[i].clone());
}

/// The `base_2b` function (FIPS 205, Algorithm 4): splits a byte string into `count` consecutive
/// `b`-bit big-endian values, as u32 words.
pub fn base_2b_u32<B: Backend>(
    allocator: &Allocator<B>,
    bytes: &[WordRef<B, u8>],
    b: usize,
    count: usize,
) -> Vec<WordRef<B, u32>> {
    assert!(1 <= b && b <= 25, "base_2b requires 1 <= b <= 25");
    assert!(
        bytes.len() * 8 >= count * b,
        "base_2b requires at least ceil(count*b/8) input bytes"
    );
    let zero = allocator.alloc(0u8);
    let mut out: Vec<WordRef<B, u32>> = Vec::with_capacity(count);
    for i in 0..count {
        let start_bit = i * b;
        let start_byte = start_bit / 8;
        let window_bytes: Vec<WordRef<B, u8>> = (0..4)
            .map(|k| {
                bytes
                    .get(start_byte + k)
                    .cloned()
                    .unwrap_or_else(|| zero.clone())
            })
            .collect();
        let window = WordRef::<B, u32>::from_be_bytes(window_bytes)
            .ok()
            .expect("4 window bytes");
        out.push((window << (start_bit - 8 * start_byte)) >> (32 - b));
    }
    return out;
}
