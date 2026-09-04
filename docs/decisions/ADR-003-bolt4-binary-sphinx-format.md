# ADR-003: BOLT #4 Sphinx Binary 1366-Byte Packet Format & Backward Compatibility

## Status

Accepted / Implemented

## Context

Standard Lightning onion routing (BOLT #4) requires a fixed-size **1366-byte binary wire format** with ChaCha20 stream cipher encryption, per-hop blinding, and filler byte padding.

Previously, the codebase used JSON string serialization for the routing payload. While convenient for human inspection in tests, it leaked the route length through packet size variations and lacked byte-level fidelity with the Lightning specification.

## Decision

We implemented full dual-mode support in `payment_communities.protocols.sphinx`:

1. **BOLT #4 Binary Standard (`create_bolt4_binary_packet` / `unwrap_bolt4_binary_packet`)**:
   - Total packet size: exactly 1366 bytes:
     - 1 byte `version` (`0x00`)
     - 33 bytes compressed `ephemeral_key`
     - 1300 bytes encrypted `routing_info`
     - 32 bytes `hmac`
   - ChaCha20 stream cipher with zero-nonce generates pseudo-random filler bytes (`_generate_bolt4_filler`).
   - Intermediary nodes pad the incoming 1300 bytes with 1300 zeros, deobfuscate using a 2600-byte ChaCha20 stream, extract their 65-byte hop payload, and forward the next 1300 bytes.
2. **Dual-Mode Auto-Detection in `unwrap_onion_packet`**:
   - `SphinxPacket.is_bolt4_binary` checks if `routing_info_hex` matches 1300 bytes (2600 hex chars).
   - If true, routes to `unwrap_bolt4_binary_packet`.
   - If false (JSON string format), routes to legacy JSON unwrap logic.

## Consequences

- **Positive**: Exact compliance with Lightning BOLT #4 onion routing cryptography.
- **Positive**: 100% backward compatibility with all existing test cases (`test_sphinx.py`, `test_sphinx_hardened.py`).
