// SPDX-License-Identifier: LGPL-3.0-or-later

//! Validates the key-generation and verification circuits against the reference `slh-dsa`
//! (RustCrypto) implementation, for the SHAKE-128s and SHAKE-128f parameter sets.
//!
//! Reference keys and signatures are generated from a seeded RNG; the circuits are executed and
//! their recomputed `PK.root` output compared against the reference public key. The 128s
//! key-generation circuit builds a full 512-leaf XMSS tree (~290k in-circuit SHAKE256 calls), so
//! its test is `#[ignore]`d for regular runs; run it explicitly in release mode.

mod common;

use common::{KeygenCircuit, VerifyCircuit};
use rand::{SeedableRng, rngs::StdRng};
use slh_dsa::{
    ParameterSet, Sha2_128f, Sha2_128s, Shake128f, Shake128s, SigningKey, signature::Signer,
};
use zkboo::{
    crypto::{HashPRG, Hasher},
    executor::{OwnedFlexibleWordPool, exec},
    prover::{prove, views::OwnedFlexibleWordTriplePool},
    verifier::{replay::OwnedFlexibleWordPairPool, verify},
};
use zkboo_slhdsa::{
    N, SLH_DSA_SHA2_128F, SLH_DSA_SHA2_128S, SLH_DSA_SHAKE_128F, SLH_DSA_SHAKE_128S, SlhDsaParams,
};
use zkboo::executor::ExecOptions;
use zkboo::prover::proof::ProofOptions;
use zkboo::verifier::VerifyOptions;
use zeroize::Zeroize;

/// A [Hasher] backed by BLAKE3, producing 32-byte digests.
#[derive(Debug)]
struct Blake3Hasher {
    inner: blake3::Hasher,
}

impl Hasher for Blake3Hasher {
    type Digest = [u8; 32];
    const DIGEST_SIZE: usize = 32;

    fn new() -> Self {
        return Self {
            inner: blake3::Hasher::new(),
        };
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize_into(&mut self, out: &mut Self::Digest) {
        let result = self.inner.finalize();
        out.copy_from_slice(result.as_bytes());
        self.inner.reset();
    }
}

impl Zeroize for Blake3Hasher {
    fn zeroize(&mut self) {
        self.inner.reset();
    }
}

type WP = OwnedFlexibleWordPool<usize>;

/// Reference key material and a reference signature over `MSG`, from a seeded RNG.
struct Reference {
    sk_seed: [u8; N],
    pk_seed: [u8; N],
    pk_root: [u8; N],
    sig: Vec<u8>,
}

const MSG: &[u8] = b"zkboo-slhdsa reference message";

/// The internal message `M'` for the pure external interface with empty context.
fn internal_msg() -> Vec<u8> {
    return [&[0u8, 0u8], MSG].concat();
}

fn reference<P: ParameterSet>() -> Reference {
    let mut rng = StdRng::seed_from_u64(0x5145_2026);
    let sk = SigningKey::<P>::new(&mut rng);
    let sk_bytes = sk.to_bytes();
    return Reference {
        sk_seed: sk_bytes[..N].try_into().unwrap(),
        pk_seed: sk_bytes[2 * N..3 * N].try_into().unwrap(),
        pk_root: sk_bytes[3 * N..4 * N].try_into().unwrap(),
        sig: sk.sign(MSG).to_vec(),
    };
}

fn check_keygen<P: ParameterSet>(params: &'static SlhDsaParams) {
    let reference = reference::<P>();
    let out = exec::<_, WP, _>(&KeygenCircuit {
        sk_seed: reference.sk_seed,
        pk_seed: reference.pk_seed,
        params,
    }, ExecOptions::new())
    .u8;
    assert_eq!(out, reference.pk_root.to_vec());
}

fn check_verify<P: ParameterSet>(params: &'static SlhDsaParams) {
    let reference = reference::<P>();
    assert_eq!(reference.sig.len(), params.sig_len());
    let out = exec::<_, WP, _>(&VerifyCircuit {
        msg: internal_msg(),
        sig: reference.sig,
        pk_seed: reference.pk_seed,
        pk_root: reference.pk_root,
        params,
    }, ExecOptions::new())
    .u8;
    assert_eq!(out, reference.pk_root.to_vec());
}

#[test]
fn test_keygen_128f() {
    check_keygen::<Shake128f>(&SLH_DSA_SHAKE_128F);
}

#[test]
#[ignore = "builds a 512-leaf XMSS tree in-circuit; run explicitly in release mode"]
fn test_keygen_128s() {
    check_keygen::<Shake128s>(&SLH_DSA_SHAKE_128S);
}

#[test]
fn test_verify_128s() {
    check_verify::<Shake128s>(&SLH_DSA_SHAKE_128S);
}

#[test]
fn test_verify_128f() {
    check_verify::<Shake128f>(&SLH_DSA_SHAKE_128F);
}

#[test]
#[ignore = "proves and verifies a full 128s verification circuit; run explicitly in release mode"]
fn test_verify_128s_zkboo_proof() {
    type H = Blake3Hasher;
    type PS = HashPRG<H>;
    type PV = HashPRG<H>;
    type S = [u8; 32];
    type WTP = OwnedFlexibleWordTriplePool<usize>;
    type WPP = OwnedFlexibleWordPairPool<usize>;
    let reference = reference::<Shake128s>();
    let circuit = VerifyCircuit {
        msg: internal_msg(),
        sig: reference.sig,
        pk_seed: reference.pk_seed,
        pk_root: reference.pk_root,
        params: &SLH_DSA_SHAKE_128S,
    };
    let expected_output = exec::<_, WP, _>(&circuit, ExecOptions::new());
    assert_eq!(expected_output.u8, reference.pk_root.to_vec());
    let proof = prove::<_, H, PS, PV, S, _, WTP, _>(&circuit, 2, b"test seed entropy", &[], ProofOptions::new());
    let is_valid = verify::<_, H, PV, S, WPP, _>(&circuit, &expected_output, &proof, &[], VerifyOptions::new())
        .expect("proof verification errored");
    assert!(is_valid, "ZKBoo proof of SLH-DSA verification is invalid");
}

#[test]
fn test_keygen_sha2_128f() {
    check_keygen::<Sha2_128f>(&SLH_DSA_SHA2_128F);
}

#[test]
#[ignore = "builds a 512-leaf XMSS tree in-circuit; run explicitly in release mode"]
fn test_keygen_sha2_128s() {
    check_keygen::<Sha2_128s>(&SLH_DSA_SHA2_128S);
}

#[test]
fn test_verify_sha2_128s() {
    check_verify::<Sha2_128s>(&SLH_DSA_SHA2_128S);
}

#[test]
fn test_verify_sha2_128f() {
    check_verify::<Sha2_128f>(&SLH_DSA_SHA2_128F);
}

#[test]
fn test_verify_128s_rejects_tampered_signature() {
    let reference = reference::<Shake128s>();
    let mut sig = reference.sig;
    sig[N] ^= 0x01;
    let out = exec::<_, WP, _>(&VerifyCircuit {
        msg: internal_msg(),
        sig,
        pk_seed: reference.pk_seed,
        pk_root: reference.pk_root,
        params: &SLH_DSA_SHAKE_128S,
    }, ExecOptions::new())
    .u8;
    assert_ne!(out, reference.pk_root.to_vec());
}

#[test]
fn test_verify_128s_rejects_wrong_message() {
    let reference = reference::<Shake128s>();
    let out = exec::<_, WP, _>(&VerifyCircuit {
        msg: [&[0u8, 0u8], b"a different message".as_slice()].concat(),
        sig: reference.sig,
        pk_seed: reference.pk_seed,
        pk_root: reference.pk_root,
        params: &SLH_DSA_SHAKE_128S,
    }, ExecOptions::new())
    .u8;
    assert_ne!(out, reference.pk_root.to_vec());
}
