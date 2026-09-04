# Payment Communities: Architectural & Theoretical Documentation Suite

Welcome to the comprehensive technical and theoretical documentation of **Payment Communities**, a production-grade educational and experimental implementation of Bitcoin Layer 2 Lightning Network protocols, Taproot smart contracts, and cryptographic payment routing.

---

## 📚 Documentation Index

### 1. Fundamental Theory (`docs/theory/`)

- [**01. Bitcoin Layer 1 Foundations**](theory/01_bitcoin_layer1.md): UTXO model, script execution engine, Segregated Witness (v0 vs v1 Taproot), BIP 141/143 vs BIP 341/342, timelocks (CSV vs CLTV), and txid malleability.
- [**02. The Lightning Network Mechanics**](theory/02_lightning_network.md): Bidirectional payment channels, 2-of-2 multisig funding, asymmetric commitment transactions, revocation keys, and multi-hop routing fees.
- [**03. Channel State Machine & HTLCs**](theory/03_channel_state_machine.md): Formal state transition model, two-phase commitment synchronization, BOLT #3 HTLC script execution (off-chain vs on-chain 2nd stage), and timeout handling.
- [**04. Punishment (Poon-Dryja) vs. Eltoo (LN-Symmetric)**](theory/04_punishment_vs_eltoo.md): Toxic state dilemma, penalty mechanisms vs update transactions, state sequence clamping, and BIP 118 `SIGHASH_ANYPREVOUT`.
- [**05. Modern Cryptography & Privacy**](theory/05_cryptography.md): ECDSA vs BIP 340 Schnorr signatures, MuSig2 key aggregation, PTLCs and Schnorr adaptor signatures, BOLT #3 48-order Shachain, and BOLT #4 Sphinx onion routing.

### 2. Architecture & Systems (`docs/architecture/`)

- [**Docker Isolated Development Environment**](architecture/docker_environment.md): Bitcoin Core Regtest orchestration, automatic block mining, faucet, P2P node daemons, Watchtowers, and Submarine Swap coordinators.

### 3. Architectural Decision Records (`docs/decisions/`)

- [**ADR-001: BIP 118 (SIGHASH_ANYPREVOUT) Eltoo Simulation & Compromise**](decisions/ADR-001-sighash-anyprevout-eltoo.md)
- [**ADR-002: SegWit v0 vs SegWit v1 (Taproot) ECDSA & Schnorr Boundaries**](decisions/ADR-002-segwit-v0-vs-taproot-schnorr.md)
- [**ADR-003: BOLT #4 Sphinx Binary 1366-Byte Packet Format & Legacy Compatibility**](decisions/ADR-003-bolt4-binary-sphinx-format.md)
- [**ADR-004: BOLT #3 48-Order Shachain vs Flat Storage Architecture**](decisions/ADR-004-bolt3-shachain-revocation-storage.md)
- [**ADR-005: ACID SQLite Storage Engine with WAL Mode**](decisions/ADR-005-sqlite-wal-persistence-engine.md)
- [**ADR-006: Asynchronous TCP P2P Daemon Framing (BOLT #1/8)**](decisions/ADR-006-async-p2p-daemon-framing.md)
- [**ADR-007: Submarine Swap Cross-Layer Liquidity Architecture**](decisions/ADR-007-submarine-swap-cross-layer-architecture.md)

---

## 🛠️ Quick Commands

```bash
# Launch Docker isolated development environment
./scripts/dev-up.sh

# Run multi-hop payment routing simulation
payment-communities simulate

# Run BOLT #3 Shachain compression demo
payment-communities shachain-demo

# Run Taproot PTLC adaptor signature demo
payment-communities ptlc-demo

# Run Atomic Submarine Swap cross-layer demo
payment-communities swaps-demo
```
