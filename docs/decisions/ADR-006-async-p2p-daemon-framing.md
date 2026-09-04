# ADR-006: Asynchronous TCP P2P Daemon Framing (BOLT #1/8)

## Status

Accepted / Implemented

## Context

Nodes in the original codebase existed as in-memory Python objects stored in a single process dictionary (`nodes['Alice']`). Invocations like `open_channel` or `update_add_htlc` were synchronous local method calls.

In a real network, nodes run as independent daemons across separate machines or containers, communicating over TCP sockets using binary message framing.

## Decision

We implemented an `asyncio` TCP P2P server daemon in `payment_communities.network.daemon`:

1. **Binary Message Framing**:
   - Each network packet begins with a 4-byte header:
     - `msg_type`: 2 bytes big-endian (e.g. `16` for `init`, `32` for `open_channel`, `128` for `update_add_htlc`).
     - `msg_len`: 2 bytes big-endian specifying payload length (max 65,535 bytes).
     - `payload`: raw UTF-8 JSON or binary data.
2. **Event-Driven Dispatch**:
   - `NodeDaemon` registers asynchronous callbacks via `register_handler(msg_type, callback)`.
   - Incoming messages are parsed continuously from the stream without buffer fragmentation.
3. **Heartbeat & Peer Lifecycle**:
   - Implements `MSG_PING` (`18`) and `MSG_PONG` (`19`) keepalive messages.
   - Clean disconnection handling and connection pooling across peers.

## Consequences

- **Positive**: Nodes can be run in separate Docker containers or independent terminals communicating across real TCP/IP networks.
- **Positive**: Directly mirrors the BOLT #1 framing architecture.
