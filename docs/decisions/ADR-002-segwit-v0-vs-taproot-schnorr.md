# ADR-002: SegWit v0 vs SegWit v1 (Taproot) Cryptographic Boundaries

## Status

Accepted / Implemented

## Context

In early versions of this codebase, Schnorr signatures were used directly inside SegWit v0 (`P2WSH` / `bc1q...`) scripts with `OP_CHECKSIG`.

However, in Bitcoin consensus rules:

- **SegWit v0 (BIP 141 / 143)**: Evaluates `OP_CHECKSIG` strictly using **DER-encoded ECDSA signatures** (71-73 bytes). Pushing a 64-byte Schnorr signature to a SegWit v0 `OP_CHECKSIG` causes a consensus script verification failure (`SCRIPT_ERR_SIG_DER`).
- **SegWit v1 Taproot (BIP 340 / 341 / 342)**: Native Taproot script execution (`Tapscript`) strictly evaluates **BIP 340 64-byte Schnorr signatures**.

## Decision

We established a strict separation of cryptographic domains across the codebase:

1. **SegWit v0 Operations (P2WPKH & P2WSH)**:
   - Funding 2-of-2 multisig, standard Poon-Dryja commitment transactions, and BOLT #3 HTLC scripts strictly use **canonical DER ECDSA signatures** with `SIGHASH_ALL` per BIP 143.
2. **SegWit v1 Taproot Operations (P2TR)**:
   - Dedicated module `payment_communities.bitcoin.taproot` implements BIP 340 tagged hashes, BIP 340 Schnorr signing and verification (`schnorr_sign`, `schnorr_verify`), BIP 341 TapTweak output key derivation (`taproot_tweak_pubkey`), and BIP 350 Bech32m address encoding (`bc1p...`).
   - Point Time-Locked Contracts (PTLCs) and Schnorr Adaptor Signatures natively settle against Taproot P2TR outputs via `create_taproot_ptlc_settlement_transaction`.
3. **Consensus Interpreter Support**:
   - `WitnessV1TaprootProgram` was added to `interpreter.py`, properly validating 64-byte Schnorr signatures against 32-byte x-only public keys.

## Consequences

- **Positive**: Complete alignment with real Bitcoin Core consensus rules. SegWit v0 scripts pass strict DER validation, while Taproot scripts pass strict BIP 340 verification.
- **Positive**: Demonstrates both the current Lightning standard (ECDSA SegWit v0) and the future Lightning standard (Taproot PTLCs).
