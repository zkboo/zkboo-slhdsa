// SPDX-License-Identifier: LGPL-3.0-or-later

//! SLH-DSA parameter sets (FIPS 205, Table 2), restricted to security category 1, for which the
//! security parameter is `n` = [N] = 16 bytes and the WOTS+ Winternitz parameter is `w` = 16
//! (`lg_w` = 4). Both the SHAKE and the SHA2 hash instantiations are supported.

/// The security parameter `n` in bytes: the size of hash nodes, seeds, and the public-key root.
pub const N: usize = 16;

/// The number of WOTS+ hash chains `len = len1 + len2`: 32 message digits (two per byte of an
/// `n`-byte value at `lg_w` = 4) plus 3 checksum digits.
pub const WOTS_LEN: usize = 35;

/// The hash-function instantiation of an SLH-DSA parameter set (FIPS 205, §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashInstantiation {
    /// SHAKE256 for every function, with the full 32-byte address.
    Shake,
    /// SHA-256 for every function (security category 1), with the compressed 22-byte address.
    Sha2,
}

/// An SLH-DSA parameter set (with `n` = [N] and `lg_w` = 4 fixed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlhDsaParams {
    /// The hash-function instantiation.
    pub hash: HashInstantiation,
    /// The total hypertree height `h`.
    pub h: usize,
    /// The number of hypertree layers `d`.
    pub d: usize,
    /// The height `h' = h/d` of each XMSS tree.
    pub h_prime: usize,
    /// The number of FORS trees `k`.
    pub k: usize,
    /// The height `a` of each FORS tree.
    pub a: usize,
    /// The message-digest length `m` in bytes.
    pub m: usize,
}

/// The SLH-DSA-SHAKE-128s ("small") parameter set.
pub const SLH_DSA_SHAKE_128S: SlhDsaParams = SlhDsaParams {
    hash: HashInstantiation::Shake,
    h: 63,
    d: 7,
    h_prime: 9,
    k: 14,
    a: 12,
    m: 30,
};

/// The SLH-DSA-SHAKE-128f ("fast") parameter set.
pub const SLH_DSA_SHAKE_128F: SlhDsaParams = SlhDsaParams {
    hash: HashInstantiation::Shake,
    h: 66,
    d: 22,
    h_prime: 3,
    k: 33,
    a: 6,
    m: 34,
};

/// The SLH-DSA-SHA2-128s ("small") parameter set.
pub const SLH_DSA_SHA2_128S: SlhDsaParams = SlhDsaParams {
    hash: HashInstantiation::Sha2,
    ..SLH_DSA_SHAKE_128S
};

/// The SLH-DSA-SHA2-128f ("fast") parameter set.
pub const SLH_DSA_SHA2_128F: SlhDsaParams = SlhDsaParams {
    hash: HashInstantiation::Sha2,
    ..SLH_DSA_SHAKE_128F
};

impl SlhDsaParams {
    /// The signature length in bytes: `(1 + k(a+1) + h + d·len) · n`.
    pub const fn sig_len(&self) -> usize {
        return N * (1 + self.k * (self.a + 1) + self.h + self.d * WOTS_LEN);
    }

    /// The public-key length in bytes: `PK.seed ‖ PK.root`.
    pub const fn pk_len(&self) -> usize {
        return 2 * N;
    }
}
