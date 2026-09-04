# ADR-007: Submarine Swap Cross-Layer Liquidity Architecture

## Status

Accepted / Implemented

## Context

Payment channels require pre-funded liquidity. If a node runs out of inbound liquidity (its inbound capacity is depleted), it cannot receive additional Lightning payments without closing the channel or rebalancing across another route.

**Submarine Swaps** allow trustless atomic swaps between on-chain Bitcoin (Layer 1) and off-chain Lightning satoshis (Layer 2), enabling non-disruptive channel liquidity management:

- **Loop In**: Convert on-chain UTXOs into off-chain Lightning channel balance.
- **Loop Out**: Convert off-chain Lightning channel balance into on-chain UTXOs (refilling inbound receiving capacity).

## Decision

We implemented an automated Submarine Swap coordinator daemon in `payment_communities.protocols.swap_server`:

1. **Loop In Workflow**:
   - User deposits on-chain to a P2WSH HTLC address locking funds with payment hash $H$ and timeout $T$.
   - Server observes funding transaction, pays user off-chain via Lightning invoice with hash $H$.
   - User settles Lightning payment by releasing preimage $R$.
   - Server takes preimage $R$ and executes `create_submarine_swap_claim_tx`, sweeping the on-chain HTLC.
2. **Loop Out Workflow**:
   - User locks off-chain Lightning HTLC with payment hash $H$.
   - Server broadcasts on-chain HTLC with payment hash $H$.
   - User claims on-chain HTLC with preimage $R$.
   - Server extracts $R$ from the on-chain transaction's witness stack and uses it to settle the off-chain Lightning HTLC.
3. **Refund Safety**:
   - If either party abandons the swap, the funder safely reclaims 100% of their funds after timeout $T$ via `create_submarine_swap_refund_tx`.

## Consequences

- **Positive**: Complete atomic liquidity rebalancing between L1 and L2 without trusting the swap provider.
- **Positive**: Directly verifiable using our `ScriptInterpreter` for both claim and refund execution paths.
