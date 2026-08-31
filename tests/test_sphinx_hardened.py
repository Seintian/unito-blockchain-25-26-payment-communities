"""
Hardened BOLT #4 Sphinx Onion Routing Test Suite.
Verifies multi-hop ECDH onion routing, per-hop ephemeral public key blinding (unlinkability),
public key input normalization, tamper resistance, and route boundary conditions.
"""

import pytest

from payment_communities.domain.node import Node
from payment_communities.exceptions import PaymentCommunityError
from payment_communities.protocols.sphinx import (
    SphinxPacket,
    create_onion_packet,
    unwrap_onion_packet,
)


class TestSphinxHardened:
    """Hardened test suite for Sphinx onion packet creation and blinded unwrapping."""

    def test_ephemeral_key_blinding_across_hops(self):
        """Validates that each hop in a 4-hop route receives a unique blinded ephemeral public key."""
        nodes = [Node(f"Node_{i}") for i in range(4)]
        node_pubkeys = {n.alias: n.pubkey_bytes for n in nodes}

        route_hops = [
            ("Node_0", "Node_1", 10_000, 200),
            ("Node_1", "Node_2", 10_000, 160),
            ("Node_2", "Node_3", 10_000, 120),
            ("Node_3", "", 10_000, 80),
        ]

        # Origin builds Sphinx packet using recipient public keys
        packet0 = create_onion_packet(route_hops, node_pubkeys)

        # Hop 0 unwraps
        payload0, packet1 = unwrap_onion_packet(
            packet0, node_wif_key=str(nodes[0].secret)
        )
        assert payload0.next_hop == "Node_1"
        assert packet1 is not None

        # Ephemeral key MUST be blinded between Hop 0 and Hop 1 (E0 != E1)
        assert packet0.ephemeral_key_hex != packet1.ephemeral_key_hex

        # Hop 1 unwraps
        payload1, packet2 = unwrap_onion_packet(
            packet1, node_wif_key=str(nodes[1].secret)
        )
        assert payload1.next_hop == "Node_2"
        assert packet2 is not None
        assert packet1.ephemeral_key_hex != packet2.ephemeral_key_hex

        # Hop 2 unwraps
        payload2, packet3 = unwrap_onion_packet(
            packet2, node_wif_key=str(nodes[2].secret)
        )
        assert payload2.next_hop == "Node_3"
        assert packet3 is not None
        assert packet2.ephemeral_key_hex != packet3.ephemeral_key_hex

        # Hop 3 unwraps final payload
        payload3, packet_final = unwrap_onion_packet(
            packet3, node_wif_key=str(nodes[3].secret)
        )
        assert payload3.next_hop == ""
        assert packet_final is None

    def test_public_key_formats_accepted(self):
        """Ensures create_onion_packet accepts 33-byte bytes, 66-char hex, and WIF strings."""
        node = Node("Bob")
        hops = [("Bob", "", 5000, 100)]

        # 1. 33-byte compressed bytes
        p1 = create_onion_packet(hops, {"Bob": node.pubkey_bytes})
        pay1, _ = unwrap_onion_packet(p1, str(node.secret))
        assert pay1.amount_sat == 5000

        # 2. 66-character hex string
        p2 = create_onion_packet(hops, {"Bob": node.pubkey_hex})
        pay2, _ = unwrap_onion_packet(p2, str(node.secret))
        assert pay2.amount_sat == 5000

        # 3. WIF private key string
        p3 = create_onion_packet(hops, {"Bob": str(node.secret)})
        pay3, _ = unwrap_onion_packet(p3, str(node.secret))
        assert pay3.amount_sat == 5000

    def test_intermediate_hop_tamper_detection(self):
        """Corrupting routing data at intermediate hop raises HMAC tamper error."""
        n1 = Node("N1")
        n2 = Node("N2")
        n3 = Node("N3")
        node_pubkeys = {n.alias: n.pubkey_bytes for n in (n1, n2, n3)}
        hops = [("N1", "N2", 1000, 140), ("N2", "N3", 1000, 100), ("N3", "", 1000, 60)]

        p1 = create_onion_packet(hops, node_pubkeys)
        _, p2 = unwrap_onion_packet(p1, str(n1.secret))
        assert p2 is not None

        # Adversary corrupts 1 byte of encrypted payload at hop 2
        raw = bytearray.fromhex(p2.routing_info_hex)
        raw[10] ^= 0xFF
        corrupted_p2 = SphinxPacket(
            ephemeral_key_hex=p2.ephemeral_key_hex,
            routing_info_hex=raw.hex(),
            hmac_hex=p2.hmac_hex,
        )

        with pytest.raises(PaymentCommunityError, match="HMAC integrity check failed"):
            unwrap_onion_packet(corrupted_p2, str(n2.secret))
