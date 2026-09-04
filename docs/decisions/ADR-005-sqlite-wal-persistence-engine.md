# ADR-005: ACID SQLite Storage Engine with WAL Mode

## Status

Accepted / Implemented

## Context

The initial storage engine relied on rewriting a single JSON file (`network_state.json`) with an atomic file swap (`.tmp` -> rename).

While functional for single-threaded CLI demos, this design exhibits critical limitations:

1. **Concurrency**: Multiple node processes or daemon threads cannot perform concurrent reads and writes without file lock contention or overwriting each other's updates.
2. **Crash Resilience**: Writing the entire network state on every micro-payment update degrades performance as channel count grows.
3. **Queryability**: Querying active HTLCs by payment hash or lookup of watchtower hints requires deserializing the entire global state into memory.

## Decision

We implemented `SqliteStorageEngine` in `payment_communities.storage.sqlite`:

1. **WAL Mode (Write-Ahead Logging)**:
   - Configured with `PRAGMA journal_mode = WAL;`, `PRAGMA synchronous = NORMAL;`, and `PRAGMA foreign_keys = ON;`.
   - Allows concurrent readers while a single writer updates channel states without blocking.
2. **Relational Schema**:
   - `channels`: Stores serialized channel state, party aliases, capacity, and status.
   - `htlcs`: Tracks individual active HTLC contracts indexed by `channel_id` and `hash_lock`.
   - `shachain`: Persists compact Shachain tree slots for each channel.
   - `preimages`: Fast indexed key-value lookup of discovered payment preimages.
   - `watchtower_hints`: Stores 16-byte txid prefix hints mapped to encrypted penalty blobs.
3. **Backward Compatibility**:
   - Provides `save_network_state` and `load_network_state` returning the standard `NetworkState` Pydantic model.

## Consequences

- **Positive**: High throughput, sub-millisecond ACID updates, and multi-process support for distributed containerized daemons.
- **Positive**: Zero data corruption during unexpected process termination.
