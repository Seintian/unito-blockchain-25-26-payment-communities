# ADR-001: BIP 118 (SIGHASH_ANYPREVOUT) Eltoo Simulation & Compromise

## Status

Accepted / Implemented (Simulation Model)

## Context

The Eltoo (LN-Symmetric) protocol fundamentally depends on the ability of state update transaction $U_k$ to bind to any prior state output ($U_j$, where $j < k$) or the original funding transaction without knowing in advance which previous transaction will appear on-chain.

In Bitcoin consensus, standard sighash flags (`SIGHASH_ALL`, `SIGHASH_NONE`, `SIGHASH_SINGLE`, combined with optional `SIGHASH_ANYONECANPAY`) strictly commit to the input's `COutPoint` (`txid:vout`). If the `txid` changes, the signature becomes invalid.

BIP 118 proposes `SIGHASH_ANYPREVOUT` (APO) and `SIGHASH_ANYPREVOUTANYSCRIPT` to enable rebinding signatures to any output matching a specific public key. However, **BIP 118 is a consensus soft fork proposal that has NOT yet been activated on Bitcoin Mainnet or standard public Signet**.

## Decision

We implemented a high-fidelity simulation model of Eltoo with the following design choices:

1. **Domain-Separated Sequence & Locktime Encoding**:
   - `ELTOO_BASE_LOCKTIME = 500,000,000` is used as the base threshold separating block height from UNIX timestamps.
   - State numbers ($1, 2, \dots, N$) are encoded into `tx.nLockTime = ELTOO_BASE_LOCKTIME + state_number`.
   - Relative delay between the final update transaction and the settlement transaction is enforced via `nSequence = ELTOO_SETTLEMENT_DELAY_BLOCKS` (CSV).
2. **Signature Verification Adaptor**:
   - For educational and testing execution against standard consensus interpreters (`ScriptInterpreter` and `python-bitcoinlib`), we provide an APO-compatible mock sighash calculator that omits `txin.prevout` during digest computation when evaluating Eltoo update contracts.
3. **Transparent Compromise Documentation**:
   - All CLI output and documentation explicitly notes that until BIP 118 is soft-forked into Bitcoin Core, Eltoo remains experimental on specialized testnets (like Inquisition).

## Consequences

- **Positive**: Developers and students can experiment with Eltoo's symmetric state replacement, verify state succession, and test settlement mechanics today without waiting for a Bitcoin Core soft fork.
- **Negative**: These transactions cannot be directly broadcast to live Bitcoin Mainnet without consensus rejections (`non-mandatory-script-verify-flag`).
