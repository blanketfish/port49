# Project Wycheproof vectors

Source: https://github.com/C2SP/wycheproof, `testvectors_v1/`, at commit
`3fa63dd0344abb611f1fb1d77e119938603ea230`.

Files (unmodified):

- `ecdsa_secp256r1_sha256_p1363_test.json` (ES256, `r||s` form)
- `ecdsa_secp384r1_sha384_p1363_test.json` (ES384)
- `rsa_signature_2048_sha256_test.json` (RS256, PKCS #1 v1.5)
- `rsa_pss_2048_sha256_mgf1_32_test.json` (PS256, 32-byte salt)
- `ed25519_test.json` (EdDSA)

Licence: Apache-2.0, as port49's.

A refresh is a new commit of the five files with the commit above updated.
No vector is skipped by `wycheproof_test.go`.
