# ACVP test vectors

Official NIST FIPS 205 gen/val test vectors, extracted from the [ACVP-Server](https://github.com/usnistgov/ACVP-Server) repository (`gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json` and `gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json`, commit `112690e8484d`, retrieved 2026-08-19), restricted to the security-category-1 parameter sets supported by this crate (SLH-DSA-SHAKE-128s/128f and SLH-DSA-SHA2-128s/128f).

- `acvp_keygen_shake128.json` / `acvp_keygen_sha2_128.json` — all key-generation cases: `skSeed`, `pkSeed` → `pk` (= `PK.seed ‖ PK.root`).
- `acvp_sigver_shake128.json` / `acvp_sigver_sha2_128.json` — all signature-verification cases for the `internal` interface (message is the internal `M'`) and the `pure` external interface (message is raw, with a `context`; `M' = 0x00 ‖ len(ctx) ‖ ctx ‖ M`), with the expected `testPassed` outcome and the failure `reason`. Cases for the pre-hash external interface (HashSLH-DSA) are omitted as out of scope.

All values are uppercase hex, as in the ACVP source. Fields other than the ones above (e.g. secret keys and signing randomness for sigVer) are stripped.
