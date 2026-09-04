"""
Unit tests for async P2P node daemon and BOLT message framing.
"""

import asyncio

import pytest

from payment_communities.network.daemon import (
    MSG_OPEN_CHANNEL,
    MSG_UPDATE_ADD_HTLC,
    NodeDaemon,
    P2PMessage,
)


def test_p2p_message_serialization():
    msg = P2PMessage(msg_type=MSG_OPEN_CHANNEL, payload={"funding_sat": 50_000})
    raw = msg.serialize()
    # 2 bytes type + 2 bytes len + payload
    assert len(raw) >= 4
    header = raw[:4]
    payload = raw[4:]
    deserialized = P2PMessage.deserialize(header, payload)
    assert deserialized.msg_type == MSG_OPEN_CHANNEL
    assert deserialized.payload["funding_sat"] == 50_000


@pytest.mark.asyncio
async def test_node_daemon_communication():
    alice = NodeDaemon("Alice", "127.0.0.1", 29735)
    bob = NodeDaemon("Bob", "127.0.0.1", 29736)

    received_htlcs = []

    def on_htlc(peer, msg):
        received_htlcs.append((peer.peer_alias, msg.payload))

    bob.register_handler(MSG_UPDATE_ADD_HTLC, on_htlc)

    await alice.start()
    await bob.start()

    try:
        # Alice connects to Bob
        await alice.connect_to_peer("Bob", "127.0.0.1", 29736)
        await asyncio.sleep(0.05)

        # Alice sends HTLC to Bob
        await alice.send_to_peer(
            "Bob",
            P2PMessage(
                msg_type=MSG_UPDATE_ADD_HTLC,
                payload={"amount_sat": 10_000, "payment_hash": "deadbeef"},
            ),
        )
        await asyncio.sleep(0.05)

        assert len(received_htlcs) == 1
        assert received_htlcs[0][0] == "Alice"
        assert received_htlcs[0][1]["amount_sat"] == 10_000

    finally:
        await alice.stop()
        await bob.stop()
