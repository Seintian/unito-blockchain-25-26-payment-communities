"""
Unit tests for BOLT #4 1366-byte binary Sphinx onion routing packet creation and unwrapping.
"""

import pytest

from payment_communities.bitcoin.utils import generate_keypair
from payment_communities.exceptions import PaymentCommunityError
from payment_communities.protocols.sphinx import (
    BOLT4_HEADER_SIZE,
    SphinxPacket,
    create_bolt4_binary_packet,
    unwrap_bolt4_binary_packet,
    unwrap_onion_packet,
)


def test_bolt4_packet_binary_serialization():
    _k1, pub1 = generate_keypair()
    _k2, pub2 = generate_keypair()
    hops = [("node1", "node2", 10_000, 144), ("node2", "", 9_000, 100)]

    node_pubkeys = {"node1": pub1, "node2": pub2}

    packet = create_bolt4_binary_packet(hops, node_pubkeys)
    raw = packet.to_binary()

    assert len(raw) == BOLT4_HEADER_SIZE  # Exactly 1366 bytes
    assert packet.is_bolt4_binary is True

    # Deserialization
    parsed = SphinxPacket.from_binary(raw)
    assert parsed.ephemeral_key_hex == packet.ephemeral_key_hex
    assert parsed.routing_info_hex == packet.routing_info_hex
    assert parsed.hmac_hex == packet.hmac_hex


def test_bolt4_multihop_roundtrip():
    k1, pub1 = generate_keypair()
    k2, pub2 = generate_keypair()
    k3, pub3 = generate_keypair()

    hops = [
        ("Alice", "Bob", 50_000, 200),
        ("Bob", "Charlie", 49_000, 150),
        ("Charlie", "", 48_000, 100),
    ]
    node_pubkeys = {"Alice": pub1, "Bob": pub2, "Charlie": pub3}

    pkt = create_bolt4_binary_packet(hops, node_pubkeys)
    assert len(pkt.to_binary()) == 1366

    # Hop 1: Alice unwraps
    p1, pkt2 = unwrap_bolt4_binary_packet(pkt, str(k1))
    assert p1.next_hop == "Bob"
    assert p1.amount_sat == 50_000
    assert p1.cltv_locktime == 200
    assert pkt2 is not None
    assert len(pkt2.to_binary()) == 1366

    # Hop 2: Bob unwraps
    p2, pkt3 = unwrap_bolt4_binary_packet(pkt2, str(k2))
    assert p2.next_hop == "Charlie"
    assert p2.amount_sat == 49_000
    assert p2.cltv_locktime == 150
    assert pkt3 is not None
    assert len(pkt3.to_binary()) == 1366

    # Hop 3: Charlie unwraps (Final destination)
    p3, pkt4 = unwrap_bolt4_binary_packet(pkt3, str(k3))
    assert p3.next_hop == ""
    assert p3.amount_sat == 48_000
    assert p3.cltv_locktime == 100
    assert pkt4 is None


def test_bolt4_auto_detect_unwrap_onion_packet():
    k1, pub1 = generate_keypair()
    hops = [("NodeA", "", 25_000, 100)]
    node_pubkeys = {"NodeA": pub1}

    pkt = create_bolt4_binary_packet(hops, node_pubkeys)
    # unwrap_onion_packet should automatically dispatch to unwrap_bolt4_binary_packet
    p, next_pkt = unwrap_onion_packet(pkt, str(k1))
    assert p.amount_sat == 25_000
    assert next_pkt is None


def test_bolt4_tampered_packet_raises():
    k1, pub1 = generate_keypair()
    hops = [("NodeA", "", 25_000, 100)]
    node_pubkeys = {"NodeA": pub1}

    pkt = create_bolt4_binary_packet(hops, node_pubkeys)
    # Tamper with routing info
    tampered_bytes = bytearray(bytes.fromhex(pkt.routing_info_hex))
    tampered_bytes[40] ^= 0xFF
    tampered_pkt = SphinxPacket(
        ephemeral_key_hex=pkt.ephemeral_key_hex,
        routing_info_hex=bytes(tampered_bytes).hex(),
        hmac_hex=pkt.hmac_hex,
    )

    with pytest.raises(PaymentCommunityError, match="HMAC integrity check failed"):
        unwrap_bolt4_binary_packet(tampered_pkt, str(k1))
