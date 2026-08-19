# ZKBoo-SLH-DSA

![Rust](https://img.shields.io/badge/rust-1.92+-orange.svg)

SLH-DSA (SPHINCS+, [FIPS 205](https://doi.org/10.6028/NIST.FIPS.205)) as [ZKBoo](https://crates.io/crates/zkboo) circuits, for the SLH-DSA-SHAKE-128s and SLH-DSA-SHAKE-128f parameter sets.

Two operations are provided:

- **Key generation** (`slh_keygen_root`): recomputes `PK.root` from the secret seed `SK.seed`, proving in zero knowledge that a public key derives from a secret seed.
- **Verification** (`slh_verify_root`): recomputes `PK.root` from a message and a signature, proving in zero knowledge that a valid signature for the message is known — the signature being the secret witness — without revealing it.

Both return the recomputed root as circuit wires: a consumer outputs those wires, and the proof verifier checks them against the known public key, so no in-circuit comparison is needed.
Signing is deliberately out of scope (it is orders of magnitude more expensive than verification and has no clear zero-knowledge use case).

```rust
use zkboo_slhdsa::{SLH_DSA_SHAKE_128S, slh_keygen_root, slh_verify_root};
// inside a Circuit::exec, with sk_seed/sig as secret input wires:
let root = slh_keygen_root(frontend.allocator(), sk_seed, &pk_seed, &SLH_DSA_SHAKE_128S);
let root = slh_verify_root(frontend.allocator(), msg, sig, &pk_seed, &pk_root, &SLH_DSA_SHAKE_128S);
```

Verification branches on values derived from the message digest (WOTS+ chain starts, Merkle authentication-path directions, tree indices), which are secret wires in the circuit; all such branching is replaced by fixed-work computation with masked selections, so the circuit's control flow — and hence the ZKBoo transcript shape — is independent of the witness.
All hashing is in-circuit SHAKE256 via [`zkboo-keccak`](https://crates.io/crates/zkboo-keccak).

Approximate circuit sizes, in in-circuit SHAKE256 calls: verification ~4.3k (128s) / ~12.5k (128f); key generation ~4.5k (128f) / ~290k (128s, a full 512-leaf XMSS tree).

## Project structure

- `src/params.rs` — the two parameter sets and derived sizes.
- `src/address.rs` — the 32-byte hash address `ADRS`, with constant and wire field setters.
- `src/hashes.rs` — the SHAKE instantiation of `F`, `H`, `T_l`, `PRF`, `H_msg`.
- `src/util.rs` — masked selection, conditional swaps, and `base_2b` bit parsing.
- `src/wots.rs`, `src/xmss.rs`, `src/fors.rs` — the three component schemes.
- `src/slh.rs` — the top-level key-generation and verification circuits.

Validated end-to-end against the reference [`slh-dsa`](https://crates.io/crates/slh-dsa) (RustCrypto) implementation: circuit outputs match reference public keys for both parameter sets, tampered signatures and wrong messages fail to reproduce the root, and a full ZKBoo prove/verify round-trip passes over the 128s verification circuit.
Heavy tests (`test_keygen_128s`, `test_verify_128s_zkboo_proof`) are `#[ignore]`d; run them explicitly in release mode.

## 🚧 Warning 🚧

Work in progress, not yet suitable for production. Security has not been audited.

## License

[LGPLv3 © contributors.](LICENSE)
