// SPDX-License-Identifier: LGPL-3.0-or-later

//! Validates the key-generation and verification circuits against the reference `slh-dsa`
//! (RustCrypto) implementation, for the SHAKE-128s and SHAKE-128f parameter sets.
//!
//! Reference keys and signatures are generated from a seeded RNG; the circuits are executed and
//! their recomputed `PK.root` output compared against the reference public key. The 128s
//! key-generation circuit builds a full 512-leaf XMSS tree (~290k in-circuit SHAKE256 calls), so
//! its test is `#[ignore]`d for regular runs; run it explicitly in release mode.

use rand::{SeedableRng, rngs::StdRng};
use slh_dsa::{ParameterSet, Shake128f, Shake128s, SigningKey, signature::Signer};
use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    crypto::{HashPRG, Keccak256Hasher},
    executor::{OwnedFlexibleWordPool, exec},
    prover::{prove, views::OwnedFlexibleWordTriplePool},
    verifier::{replay::OwnedFlexibleWordPairPool, verify},
};
use zkboo_slhdsa::{
    N, SLH_DSA_SHAKE_128F, SLH_DSA_SHAKE_128S, SlhDsaParams, slh_keygen_root, slh_verify_root,
};

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

struct KeygenCircuit {
    sk_seed: [u8; N],
    pk_seed: [u8; N],
    params: &'static SlhDsaParams,
}

impl Circuit for KeygenCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let sk_seed = core::array::from_fn(|i| frontend.input(self.sk_seed[i]));
        let root = slh_keygen_root(frontend.allocator(), sk_seed, &self.pk_seed, self.params);
        root.into_iter().for_each(|w| frontend.output(w));
    }
}

struct VerifyCircuit {
    msg: Vec<u8>,
    sig: Vec<u8>,
    pk_seed: [u8; N],
    pk_root: [u8; N],
    params: &'static SlhDsaParams,
}

impl Circuit for VerifyCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let allocator = frontend.allocator();
        let msg = self.msg.iter().map(|&b| allocator.alloc(b)).collect();
        let sig = self.sig.iter().map(|&b| frontend.input(b)).collect();
        let root = slh_verify_root(
            allocator,
            msg,
            sig,
            &self.pk_seed,
            &self.pk_root,
            self.params,
        );
        root.into_iter().for_each(|w| frontend.output(w));
    }
}

fn check_keygen<P: ParameterSet>(params: &'static SlhDsaParams) {
    let reference = reference::<P>();
    let out = exec::<_, WP>(&KeygenCircuit {
        sk_seed: reference.sk_seed,
        pk_seed: reference.pk_seed,
        params,
    })
    .u8;
    assert_eq!(out, reference.pk_root.to_vec());
}

fn check_verify<P: ParameterSet>(params: &'static SlhDsaParams) {
    let reference = reference::<P>();
    assert_eq!(reference.sig.len(), params.sig_len());
    let out = exec::<_, WP>(&VerifyCircuit {
        msg: internal_msg(),
        sig: reference.sig,
        pk_seed: reference.pk_seed,
        pk_root: reference.pk_root,
        params,
    })
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
    type H = Keccak256Hasher;
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
    let expected_output = exec::<_, WP>(&circuit);
    assert_eq!(expected_output.u8, reference.pk_root.to_vec());
    let proof = prove::<_, H, PS, PV, S, WTP>(&circuit, 2, b"test seed entropy", &[]);
    let is_valid = verify::<_, H, PV, S, WPP>(&circuit, &expected_output, &proof, &[])
        .expect("proof verification errored");
    assert!(is_valid, "ZKBoo proof of SLH-DSA verification is invalid");
}

#[test]
fn test_verify_128s_rejects_tampered_signature() {
    let reference = reference::<Shake128s>();
    let mut sig = reference.sig;
    sig[N] ^= 0x01;
    let out = exec::<_, WP>(&VerifyCircuit {
        msg: internal_msg(),
        sig,
        pk_seed: reference.pk_seed,
        pk_root: reference.pk_root,
        params: &SLH_DSA_SHAKE_128S,
    })
    .u8;
    assert_ne!(out, reference.pk_root.to_vec());
}

#[test]
fn test_verify_128s_rejects_wrong_message() {
    let reference = reference::<Shake128s>();
    let out = exec::<_, WP>(&VerifyCircuit {
        msg: [&[0u8, 0u8], b"a different message".as_slice()].concat(),
        sig: reference.sig,
        pk_seed: reference.pk_seed,
        pk_root: reference.pk_root,
        params: &SLH_DSA_SHAKE_128S,
    })
    .u8;
    assert_ne!(out, reference.pk_root.to_vec());
}
