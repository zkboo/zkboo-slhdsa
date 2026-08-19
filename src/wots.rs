// SPDX-License-Identifier: LGPL-3.0-or-later

//! WOTS+ one-time signatures (FIPS 205, §5) at `lg_w` = 4, i.e. `w` = 16 and `len` = 35.

use crate::{
    address::{ADRS_WOTS_PK, ADRS_WOTS_PRF, Adrs},
    hashes::{Node, f, prf, t_l},
    params::{N, WOTS_LEN},
    util::{mask_from_bit, node_from_slice, select_node},
};
use alloc::vec::Vec;
use zkboo::backend::{Backend, WordRef};

/// The Winternitz parameter `w` = 16.
pub const W: usize = 16;

/// The number of hash chains `len` = 35 (32 message digits plus 3 checksum digits).
pub const LEN: usize = WOTS_LEN;

/// The number of message digits `len1` = 32.
const LEN1: usize = 32;

/// Computes a WOTS+ public key from the secret seed (FIPS 205, Algorithm 6).
pub fn wots_pk_gen<B: Backend>(sk_seed: &Node<B>, pk_seed: &Node<B>, adrs: &Adrs<B>) -> Node<B> {
    let mut sk_adrs = adrs.clone();
    sk_adrs.set_type_and_clear(ADRS_WOTS_PRF);
    sk_adrs.copy_key_pair_from(adrs);
    let mut chain_adrs = adrs.clone();
    let mut tmp: Vec<WordRef<B, u8>> = Vec::with_capacity(LEN * N);
    for i in 0..LEN {
        sk_adrs.set_chain_const(i as u32);
        let mut v = prf(&sk_adrs, pk_seed, sk_seed);
        chain_adrs.set_chain_const(i as u32);
        for j in 0..W - 1 {
            chain_adrs.set_hash_const(j as u32);
            v = f(&chain_adrs, pk_seed, &v);
        }
        tmp.extend(v);
    }
    let mut pk_adrs = adrs.clone();
    pk_adrs.set_type_and_clear(ADRS_WOTS_PK);
    pk_adrs.copy_key_pair_from(adrs);
    return t_l(&pk_adrs, pk_seed, tmp);
}

/// Computes the `len` = 35 message digits of an `n`-byte value: its 32 nibbles (big-endian within
/// each byte) followed by the 3 checksum digits (FIPS 205, Algorithm 8, steps 1–6).
fn wots_digits<B: Backend>(adrs: &Adrs<B>, msg: &Node<B>) -> Vec<WordRef<B, u8>> {
    let allocator = adrs.allocator();
    let mut digits: Vec<WordRef<B, u8>> = Vec::with_capacity(LEN);
    for byte in msg {
        digits.push(byte.clone() >> 4);
        digits.push((byte.clone() << 4) >> 4);
    }
    // csum = Σ (w − 1 − digit); each digit is at most 15, so w − 1 − digit = digit XOR 0x0F.
    let mut csum = allocator.alloc(0u16);
    for digit in &digits {
        csum = csum + (digit.clone() ^ 0x0Fu8).cast::<u16>();
    }
    // Left-align the 12 checksum bits and split them into 3 digits.
    csum = csum << 4;
    let csum_bytes = csum.into_be_bytes();
    digits.push(csum_bytes[0].clone() >> 4);
    digits.push((csum_bytes[0].clone() << 4) >> 4);
    digits.push(csum_bytes[1].clone() >> 4);
    assert_eq!(digits.len(), LEN);
    assert_eq!(digits.len(), LEN1 + 3);
    return digits;
}

/// Recomputes a WOTS+ public key from a signature and the signed `n`-byte value (FIPS 205,
/// Algorithm 8), with message-independent control flow.
pub fn wots_pk_from_sig<B: Backend>(
    sig: &[WordRef<B, u8>],
    msg: &Node<B>,
    pk_seed: &Node<B>,
    adrs: &Adrs<B>,
) -> Node<B> {
    assert_eq!(sig.len(), LEN * N, "WOTS+ signature must be len·n bytes");
    let digits = wots_digits(adrs, msg);
    let mut chain_adrs = adrs.clone();
    let mut tmp: Vec<WordRef<B, u8>> = Vec::with_capacity(LEN * N);
    for i in 0..LEN {
        chain_adrs.set_chain_const(i as u32);
        let mut v = node_from_slice(&sig[i * N..(i + 1) * N]);
        for pos in 0..W - 1 {
            chain_adrs.set_hash_const(pos as u32);
            let fv = f(&chain_adrs, pk_seed, &v);
            // Keep v while digit > pos (the chain start has not been reached yet): the sum
            // digit + 15 − pos exceeds 15 exactly in that case, making bit 4 its indicator.
            let keep_bit = (digits[i].clone() + (W - 1 - pos) as u8) >> 4;
            v = select_node(&mask_from_bit(keep_bit), &v, &fv);
        }
        tmp.extend(v);
    }
    let mut pk_adrs = adrs.clone();
    pk_adrs.set_type_and_clear(ADRS_WOTS_PK);
    pk_adrs.copy_key_pair_from(adrs);
    return t_l(&pk_adrs, pk_seed, tmp);
}
