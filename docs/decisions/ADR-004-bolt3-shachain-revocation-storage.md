# ADR-004: BOLT #3 48-Order Shachain Revocation Storage Architecture

## Status

Accepted / Implemented

## Context

In early implementations of the Poon-Dryja channel, the `RevocationStore` stored counterparty secrets in a flat Python dictionary: `{state_index: secret}`. For a channel executing millions of payments, flat storage scales linearly ($O(N)$), consuming unbounded disk and memory.

BOLT #3 specifies **Shachain**, a compact 48-order tree structure where up to $2^{48}$ revocation secrets can be stored in at most 48 32-byte slots ($O(\log N)$ storage).

## Decision

We implemented `payment_communities.protocols.shachain`:

1. **Sender (`ShachainGenerator`)**:
   - Generates secrets using bit-flip derivation from a 32-byte root seed: `derive_shachain_secret(seed, index)`.
   - Maps commitment numbers to reversed indexes: $\text{index} = (2^{48} - 1) - \text{commitment\_number}$.
2. **Receiver (`ShachainReceiver`)**:
   - Maintains an `elements` dictionary mapping active tree slots ($0 \dots 47$) to 32-byte secret hex strings.
   - Compresses child secrets into parent ancestor nodes when newly revealed secrets allow derivation of existing slots.
   - Derives any past secret deterministically via `get_secret(index)`.
3. **Integration with RevocationStore**:
   - `RevocationStore` delegates compact secret storage and retrieval directly to `ShachainReceiver`.

## Consequences

- **Positive**: Reduces revocation secret storage footprint by >99.9% for active channels. Storing 100,000 secrets requires only a few hundred bytes instead of 3.2 MB.
- **Positive**: Exactly mirrors the revocation engine in `lnd` and `c-lightning`.
