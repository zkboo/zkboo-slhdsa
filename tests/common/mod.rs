// SPDX-License-Identifier: LGPL-3.0-or-later

//! Test circuits shared across the integration-test binaries.

use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
};
use zkboo_slhdsa::{N, SlhDsaParams, slh_keygen_root, slh_verify_root};

/// Key-generation circuit: `SK.seed` is the secret input, `PK.seed` a public constant, and the
/// recomputed `PK.root` the output.
pub struct KeygenCircuit {
    pub sk_seed: [u8; N],
    pub pk_seed: [u8; N],
    pub params: &'static SlhDsaParams,
}

impl Circuit for KeygenCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let sk_seed = core::array::from_fn(|i| frontend.input(self.sk_seed[i]));
        let root = slh_keygen_root(frontend.allocator(), sk_seed, &self.pk_seed, self.params);
        root.into_iter().for_each(|w| frontend.output(w));
    }
}

/// Verification circuit: the signature is the secret input, the internal message and public key
/// are public constants, and the recomputed `PK.root` is the output.
pub struct VerifyCircuit {
    pub msg: Vec<u8>,
    pub sig: Vec<u8>,
    pub pk_seed: [u8; N],
    pub pk_root: [u8; N],
    pub params: &'static SlhDsaParams,
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
