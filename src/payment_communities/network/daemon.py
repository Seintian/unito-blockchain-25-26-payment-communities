"""
Asynchronous P2P TCP Lightning Node Daemon with BOLT-style Message Framing.

Features:
- 2-byte Type + 2-byte Length binary header framing for peer stream parsing.
- Bi-directional P2P communication across distributed nodes (Alice, Bob, Dave).
- Message dispatching for channel negotiation, HTLC updates, and revocation exchange.
- Keepalive ping/pong heartbeat and graceful peer disconnect handling.
"""

import asyncio
import json
import logging
from collections.abc import Callable, Coroutine
from typing import Any

from pydantic import BaseModel

logger = logging.getLogger(__name__)

# BOLT #1 & #2 standard message types
MSG_INIT: int = 16
MSG_ERROR: int = 17
MSG_PING: int = 18
MSG_PONG: int = 19
MSG_OPEN_CHANNEL: int = 32
MSG_ACCEPT_CHANNEL: int = 33
MSG_FUNDING_CREATED: int = 34
MSG_FUNDING_SIGNED: int = 35
MSG_CHANNEL_READY: int = 36
MSG_UPDATE_ADD_HTLC: int = 128
MSG_UPDATE_FULFILL_HTLC: int = 130
MSG_UPDATE_FAIL_HTLC: int = 131
MSG_COMMITMENT_SIGNED: int = 132
MSG_REVOKE_AND_ACK: int = 133


class P2PMessage(BaseModel):
    """Encapsulates a P2P framed network message."""

    msg_type: int
    payload: dict[str, Any]

    def serialize(self) -> bytes:
        """Encodes message into [type: 2 bytes][len: 2 bytes][payload_json: N bytes]."""
        payload_bytes = json.dumps(self.payload).encode("utf-8")
        msg_len = len(payload_bytes)
        if msg_len > 65535:
            raise ValueError(f"Payload too large: {msg_len} bytes (max 65535)")
        header = self.msg_type.to_bytes(2, "big") + msg_len.to_bytes(2, "big")
        return header + payload_bytes

    @classmethod
    def deserialize(cls, header: bytes, payload_bytes: bytes) -> P2PMessage:
        """Decodes binary header and payload into P2PMessage."""
        if len(header) != 4:
            raise ValueError(f"Invalid header size: {len(header)} (expected 4)")
        msg_type = int.from_bytes(header[:2], "big")
        payload = json.loads(payload_bytes.decode("utf-8"))
        return cls(msg_type=msg_type, payload=payload)


class PeerConnection:
    """Represents an active peer TCP stream session."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer_alias: str = "",
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.peer_alias = peer_alias
        self._is_active = True

    async def send(self, msg: P2PMessage) -> None:
        """Sends a framed P2P message across the socket."""
        data = msg.serialize()
        self.writer.write(data)
        await self.writer.drain()

    async def receive(self) -> P2PMessage | None:
        """Reads exactly one framed message from the peer socket."""
        try:
            header = await self.reader.readexactly(4)
            msg_len = int.from_bytes(header[2:4], "big")
            payload = await self.reader.readexactly(msg_len)
            return P2PMessage.deserialize(header, payload)
        except asyncio.IncompleteReadError, ConnectionResetError:
            self._is_active = False
            return None

    def close(self) -> None:
        self._is_active = False
        self.writer.close()


class NodeDaemon:
    """
    Lightning network node P2P server daemon.
    Listens on TCP port and coordinates live communication between nodes.
    """

    def __init__(self, alias: str, host: str = "127.0.0.1", port: int = 9735) -> None:
        self.alias = alias
        self.host = host
        self.port = port
        self.peers: dict[str, PeerConnection] = {}
        self.handlers: dict[
            int,
            list[
                Callable[
                    [PeerConnection, P2PMessage],
                    Coroutine[Any, Any, None] | None,
                ]
            ],
        ] = {}
        self._server: asyncio.Server | None = None
        self._running = False
        self._tasks: list[asyncio.Task[Any]] = []

    def register_handler(
        self,
        msg_type: int,
        handler: Callable[
            [PeerConnection, P2PMessage], Coroutine[Any, Any, None] | None
        ],
    ) -> None:
        """Registers a callback handler for a given message type."""
        self.handlers.setdefault(msg_type, []).append(handler)

    async def start(self) -> None:
        """Starts TCP server and begins listening for incoming peer connections."""
        self._running = True
        self._server = await asyncio.start_server(
            self._handle_incoming_connection, self.host, self.port
        )
        logger.info(f"[{self.alias}] Node daemon listening on {self.host}:{self.port}")

    async def _handle_incoming_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = PeerConnection(reader, writer)
        task = asyncio.create_task(self._peer_read_loop(peer))
        self._tasks.append(task)

    async def connect_to_peer(
        self, peer_alias: str, host: str, port: int
    ) -> PeerConnection:
        """Establishes an outbound TCP connection to a peer daemon."""
        reader, writer = await asyncio.open_connection(host, port)
        peer = PeerConnection(reader, writer, peer_alias=peer_alias)
        self.peers[peer_alias] = peer

        # Send MSG_INIT
        await peer.send(
            P2PMessage(msg_type=MSG_INIT, payload={"sender_alias": self.alias})
        )

        task = asyncio.create_task(self._peer_read_loop(peer))
        self._tasks.append(task)
        return peer

    async def _peer_read_loop(self, peer: PeerConnection) -> None:
        """Continuous event loop reading and dispatching framed messages from a peer."""
        try:
            while self._running and peer._is_active:
                msg = await peer.receive()
                if msg is None:
                    break

                # Handle INIT handshake
                if msg.msg_type == MSG_INIT:
                    sender = msg.payload.get("sender_alias", "")
                    if sender:
                        peer.peer_alias = sender
                        self.peers[sender] = peer

                # Handle PING/PONG
                elif msg.msg_type == MSG_PING:
                    await peer.send(P2PMessage(msg_type=MSG_PONG, payload={}))
                    continue

                # Dispatch registered handlers
                handlers = self.handlers.get(msg.msg_type, [])
                for handler in handlers:
                    res = handler(peer, msg)
                    if asyncio.iscoroutine(res):
                        await res
        finally:
            if peer.peer_alias and peer.peer_alias in self.peers:
                del self.peers[peer.peer_alias]
            peer.close()

    async def send_to_peer(self, peer_alias: str, msg: P2PMessage) -> None:
        """Sends a message to an active connected peer."""
        peer = self.peers.get(peer_alias)
        if not peer:
            raise ConnectionError(f"No active connection to peer {peer_alias}")
        await peer.send(msg)

    async def stop(self) -> None:
        """Gracefully shuts down server and disconnects all peers."""
        self._running = False
        for peer in list(self.peers.values()):
            peer.close()
        self.peers.clear()

        for t in self._tasks:
            t.cancel()

        if self._server:
            self._server.close()
            await self._server.wait_closed()
