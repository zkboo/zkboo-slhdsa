# ZKBoo-SLH-DSA

![Rust](https://img.shields.io/badge/rust-1.92+-orange.svg)

SLH-DSA (SPHINCS+, [FIPS 205](https://doi.org/10.6028/NIST.FIPS.205)) as [ZKBoo](https://crates.io/crates/zkboo) circuits, for the security-category-1 parameter sets: SLH-DSA-SHAKE-128s/128f and SLH-DSA-SHA2-128s/128f (the two hash instantiations relevant to Bitcoin's BIP-360 signature-algorithm candidates).

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
All hashing is in-circuit: SHAKE256 via [`zkboo-keccak`](https://crates.io/crates/zkboo-keccak) for the SHAKE sets, SHA-256 via [`zkboo-sha2`](https://crates.io/crates/zkboo-sha2) (with the compressed 22-byte address and the MGF1-based message digest) for the SHA2 sets.

Approximate circuit sizes, in in-circuit SHAKE256 calls: verification ~4.3k (128s) / ~12.5k (128f); key generation ~4.5k (128f) / ~290k (128s, a full 512-leaf XMSS tree).

## Project structure

- `src/params.rs` — the two parameter sets and derived sizes.
- `src/address.rs` — the 32-byte hash address `ADRS`, with constant and wire field setters.
- `src/hashes.rs` — the SHAKE and SHA2 instantiations of `F`, `H`, `T_l`, `PRF`, `H_msg`.
- `src/util.rs` — masked selection, conditional swaps, and `base_2b` bit parsing.
- `src/wots.rs`, `src/xmss.rs`, `src/fors.rs` — the three component schemes.
- `src/slh.rs` — the top-level key-generation and verification circuits.

Validated end-to-end against the reference [`slh-dsa`](https://crates.io/crates/slh-dsa) (RustCrypto) implementation and against the official NIST ACVP FIPS 205 gen/val vectors (`tests/vectors/`, see its README for provenance): all keyGen cases and all sigVer cases of the internal and pure-external interfaces pass, for all four parameter sets, including adversarial cases (modified `R`/`SIG_FORS`/`SIG_HT`, modified messages, wrong-length signatures). A full ZKBoo prove/verify round-trip passes over the 128s verification circuit.
Heavy tests (the 128s key-generation cases and the proof round-trip) are `#[ignore]`d; run them explicitly in release mode.

## ⚠️ Unaudited ⚠️

The public API is stable as of 1.0.0, but this implementation has not undergone an external
security review.
Use at your own risk.

## License

[LGPLv3 © contributors.](LICENSE)
