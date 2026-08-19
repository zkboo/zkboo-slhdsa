// SPDX-License-Identifier: LGPL-3.0-or-later

//! Validates the circuits against the official NIST ACVP gen/val test vectors for FIPS 205
//! (see `tests/vectors/README.md` for provenance).
//!
//! Key generation runs every keyGen case (SHAKE and SHA2 instantiations alike), checking the recomputed `PK.root` against the vector.
//! Verification runs every sigVer case of the internal and pure-external interfaces: valid cases
//! must reproduce `PK.root` and invalid ones must not, with wrong-length signatures rejected
//! before the circuit is built. The 128s key-generation cases each build a full 512-leaf XMSS
//! tree in-circuit, so their test is `#[ignore]`d; run it explicitly in release mode.

mod common;

use common::{KeygenCircuit, VerifyCircuit};
use serde_json::Value;
use zkboo::executor::{OwnedFlexibleWordPool, exec};
use zkboo_slhdsa::{
    N, SLH_DSA_SHA2_128F, SLH_DSA_SHA2_128S, SLH_DSA_SHAKE_128F, SLH_DSA_SHAKE_128S, SlhDsaParams,
};

type WP = OwnedFlexibleWordPool<usize>;

fn params_for(parameter_set: &str) -> &'static SlhDsaParams {
    return match parameter_set {
        "SLH-DSA-SHAKE-128s" => &SLH_DSA_SHAKE_128S,
        "SLH-DSA-SHAKE-128f" => &SLH_DSA_SHAKE_128F,
        "SLH-DSA-SHA2-128s" => &SLH_DSA_SHA2_128S,
        "SLH-DSA-SHA2-128f" => &SLH_DSA_SHA2_128F,
        _ => panic!("unsupported parameter set {parameter_set}"),
    };
}

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string must have even length");
    return (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("valid hex"))
        .collect();
}

fn hex_field(case: &Value, field: &str) -> Vec<u8> {
    return hex(case[field].as_str().unwrap_or_else(|| {
        panic!("missing field {field}");
    }));
}

fn cases(fixture: &str, parameter_set: &str) -> Vec<Value> {
    let all: Vec<Value> = serde_json::from_str(fixture).expect("valid fixture JSON");
    return all
        .into_iter()
        .filter(|c| c["parameterSet"] == parameter_set)
        .collect();
}

fn keygen_fixture(parameter_set: &str) -> &'static str {
    return if parameter_set.contains("SHA2") {
        include_str!("vectors/acvp_keygen_sha2_128.json")
    } else {
        include_str!("vectors/acvp_keygen_shake128.json")
    };
}

fn sigver_fixture(parameter_set: &str) -> &'static str {
    return if parameter_set.contains("SHA2") {
        include_str!("vectors/acvp_sigver_sha2_128.json")
    } else {
        include_str!("vectors/acvp_sigver_shake128.json")
    };
}

fn run_keygen_cases(parameter_set: &str) {
    let cases = cases(keygen_fixture(parameter_set), parameter_set);
    assert!(!cases.is_empty(), "no keyGen cases for {parameter_set}");
    for case in cases {
        let tc_id = &case["tcId"];
        let sk_seed: [u8; N] = hex_field(&case, "skSeed").try_into().unwrap();
        let pk_seed: [u8; N] = hex_field(&case, "pkSeed").try_into().unwrap();
        let pk = hex_field(&case, "pk");
        let out = exec::<_, WP>(&KeygenCircuit {
            sk_seed,
            pk_seed,
            params: params_for(parameter_set),
        })
        .u8;
        assert_eq!(out, pk[N..2 * N].to_vec(), "keyGen tcId {tc_id}");
    }
}

fn run_sigver_cases(parameter_set: &str) {
    let params = params_for(parameter_set);
    let cases = cases(sigver_fixture(parameter_set), parameter_set);
    assert!(!cases.is_empty(), "no sigVer cases for {parameter_set}");
    for case in cases {
        let tc_id = &case["tcId"];
        let reason = case["reason"].as_str().unwrap_or("");
        let expected = case["testPassed"].as_bool().expect("testPassed flag");
        let pk = hex_field(&case, "pk");
        let sig = hex_field(&case, "signature");
        let msg = hex_field(&case, "message");
        // The internal interface signs the message as given; the pure external interface signs
        // M' = 0x00 ‖ len(ctx) ‖ ctx ‖ M, which the circuit's caller is responsible for building.
        let internal_msg = match case["interface"].as_str().expect("interface") {
            "internal" => msg,
            "pure" => {
                let ctx = hex_field(&case, "context");
                [&[0u8, ctx.len() as u8], ctx.as_slice(), msg.as_slice()].concat()
            }
            other => panic!("unsupported interface {other}"),
        };
        if sig.len() != params.sig_len() {
            assert!(
                !expected,
                "sigVer tcId {tc_id}: wrong-length signature must fail"
            );
            continue;
        }
        let pk_root: [u8; N] = pk[N..2 * N].try_into().unwrap();
        let out = exec::<_, WP>(&VerifyCircuit {
            msg: internal_msg,
            sig,
            pk_seed: pk[..N].try_into().unwrap(),
            pk_root,
            params,
        })
        .u8;
        assert_eq!(
            out == pk_root.to_vec(),
            expected,
            "sigVer tcId {tc_id} ({reason})"
        );
    }
}

#[test]
fn test_acvp_keygen_128f() {
    run_keygen_cases("SLH-DSA-SHAKE-128f");
}

#[test]
#[ignore = "builds ten 512-leaf XMSS trees in-circuit; run explicitly in release mode"]
fn test_acvp_keygen_128s() {
    run_keygen_cases("SLH-DSA-SHAKE-128s");
}

#[test]
fn test_acvp_sigver_128s() {
    run_sigver_cases("SLH-DSA-SHAKE-128s");
}

#[test]
fn test_acvp_sigver_128f() {
    run_sigver_cases("SLH-DSA-SHAKE-128f");
}

#[test]
fn test_acvp_keygen_sha2_128f() {
    run_keygen_cases("SLH-DSA-SHA2-128f");
}

#[test]
#[ignore = "builds ten 512-leaf XMSS trees in-circuit; run explicitly in release mode"]
fn test_acvp_keygen_sha2_128s() {
    run_keygen_cases("SLH-DSA-SHA2-128s");
}

#[test]
fn test_acvp_sigver_sha2_128s() {
    run_sigver_cases("SLH-DSA-SHA2-128s");
}

#[test]
fn test_acvp_sigver_sha2_128f() {
    run_sigver_cases("SLH-DSA-SHA2-128f");
}
