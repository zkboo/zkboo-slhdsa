// SPDX-License-Identifier: LGPL-3.0-or-later

//! The SLH-DSA hash address `ADRS` (FIPS 205, §4.2) as a 32-byte wire array.

use zkboo::backend::{Allocator, Backend, WordRef};

/// The `WOTS_HASH` address type: WOTS+ chain hashing.
pub const ADRS_WOTS_HASH: u32 = 0;
/// The `WOTS_PK` address type: WOTS+ public-key compression.
pub const ADRS_WOTS_PK: u32 = 1;
/// The `TREE` address type: XMSS Merkle-tree hashing.
pub const ADRS_TREE: u32 = 2;
/// The `FORS_TREE` address type: FORS leaf generation and Merkle-tree hashing.
pub const ADRS_FORS_TREE: u32 = 3;
/// The `FORS_ROOTS` address type: FORS root compression.
pub const ADRS_FORS_ROOTS: u32 = 4;
/// The `WOTS_PRF` address type: WOTS+ secret-value generation.
pub const ADRS_WOTS_PRF: u32 = 5;

/// An SLH-DSA hash address: 32 byte wires with typed field setters.
pub struct Adrs<B: Backend> {
    allocator: Allocator<B>,
    bytes: [WordRef<B, u8>; 32],
}

impl<B: Backend> Clone for Adrs<B> {
    fn clone(&self) -> Self {
        return Adrs {
            allocator: self.allocator.clone(),
            bytes: self.bytes.clone(),
        };
    }
}

impl<B: Backend> core::fmt::Debug for Adrs<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        return f.write_str("Adrs");
    }
}

impl<B: Backend> Adrs<B> {
    /// Creates an all-zero address.
    pub fn new(allocator: Allocator<B>) -> Self {
        let bytes = core::array::from_fn(|_| allocator.alloc(0u8));
        return Adrs { allocator, bytes };
    }

    /// Returns a clone of the allocator this address was built with.
    pub fn allocator(&self) -> Allocator<B> {
        return self.allocator.clone();
    }

    /// Returns the address bytes, for inclusion in a hash input.
    pub fn bytes(&self) -> &[WordRef<B, u8>; 32] {
        return &self.bytes;
    }

    /// Overwrites the 4 bytes at `offset` with a big-endian u32 constant.
    fn set_u32_const(&mut self, offset: usize, value: u32) {
        for (i, byte) in value.to_be_bytes().into_iter().enumerate() {
            self.bytes[offset + i] = self.allocator.alloc(byte);
        }
    }

    /// Overwrites the 4 bytes at `offset` with the big-endian bytes of a u32 wire.
    fn set_u32_wire(&mut self, offset: usize, value: &WordRef<B, u32>) {
        for (i, byte) in value.clone().into_be_bytes().into_iter().enumerate() {
            self.bytes[offset + i] = byte;
        }
    }

    /// Sets the layer address (bytes 0..4).
    pub fn set_layer(&mut self, layer: u32) {
        self.set_u32_const(0, layer);
    }

    /// Sets the tree address (bytes 4..16) from a u64 wire (the upper 4 bytes are zeroed).
    pub fn set_tree_addr_wire(&mut self, tree: &WordRef<B, u64>) {
        self.set_u32_const(4, 0);
        for (i, byte) in tree.clone().into_be_bytes().into_iter().enumerate() {
            self.bytes[8 + i] = byte;
        }
    }

    /// Sets the type (bytes 16..20) and zeroes the three type-dependent words (bytes 20..32), as
    /// prescribed for every address-type change (FIPS 205, §4.2).
    pub fn set_type_and_clear(&mut self, adrs_type: u32) {
        self.set_u32_const(16, adrs_type);
        self.set_u32_const(20, 0);
        self.set_u32_const(24, 0);
        self.set_u32_const(28, 0);
    }

    /// Sets the key-pair address (bytes 20..24) to a constant.
    pub fn set_key_pair_const(&mut self, key_pair: u32) {
        self.set_u32_const(20, key_pair);
    }

    /// Sets the key-pair address (bytes 20..24) from a u32 wire.
    pub fn set_key_pair_wire(&mut self, key_pair: &WordRef<B, u32>) {
        self.set_u32_wire(20, key_pair);
    }

    /// Copies the key-pair address (bytes 20..24) from another address.
    pub fn copy_key_pair_from(&mut self, other: &Adrs<B>) {
        for i in 20..24 {
            self.bytes[i] = other.bytes[i].clone();
        }
    }

    /// Sets the chain address (bytes 24..28) to a constant.
    pub fn set_chain_const(&mut self, chain: u32) {
        self.set_u32_const(24, chain);
    }

    /// Sets the tree height (bytes 24..28) to a constant.
    pub fn set_tree_height_const(&mut self, height: u32) {
        self.set_u32_const(24, height);
    }

    /// Sets the hash address (bytes 28..32) to a constant.
    pub fn set_hash_const(&mut self, hash: u32) {
        self.set_u32_const(28, hash);
    }

    /// Sets the tree index (bytes 28..32) to a constant.
    pub fn set_tree_index_const(&mut self, index: u32) {
        self.set_u32_const(28, index);
    }

    /// Sets the tree index (bytes 28..32) from a u32 wire.
    pub fn set_tree_index_wire(&mut self, index: &WordRef<B, u32>) {
        self.set_u32_wire(28, index);
    }
}
