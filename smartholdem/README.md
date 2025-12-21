# Schnorr Legacy Signatures (Rust)

This module implements a **legacy Schnorr signature scheme** over secp256k1 in Rust, compatible with historical Bitcoin/cryptography conventions (pre-BIP-340).

## Features

- **Signing & Verification**
  - `schnorrleg_sign(msg, seckey) → [u8; 64]` signature
  - `schnorrleg_verify(msg, sig, pubkey) → bool`
- **No BIP-340 shortcuts**
  - Full quadratic residue check for `R_y`
  - Legacy x/y handling
- **Pure Rust + secp256k1**
  - Uses `SecretKey`, `PublicKey`, and `Scalar` primitives
  - Optional optimization via libsecp256k1 internals for `is_quad_y_bytes`
- **Deterministic nonce derivation**
  - Nonce `k` is derived from the secret key and message via SHA256

## Signature Format

The generated signatures follow the format accepted by the Smartholdem blockchain. Ensure your public keys and message digests are compatible with the network's expectations.

## Notes

- Implements constant-time arithmetic where feasible, though is_quad_y_bytes can be optimized with libsecp internals for better performance.

- Provides drop-in legacy behavior for pre-BIP-340 Schnorr signatures.

- Useful for testing, compatibility layers, and historical cryptography research.

## Tested With

- Smartholdem blockchain ([https://smartholdem.io/](https://smartholdem.io/))
