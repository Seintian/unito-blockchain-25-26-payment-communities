"""
Unit tests for Sphinx Onion Encrypted Multi-Hop Packet Routing Engine.
"""

import pytest

from payment_communities.bitcoin_utils import generate_keypair
from payment_communities.exceptions import PaymentCommunityError
from payment_communities.sphinx import (
    SphinxPacket,
    create_onion_packet,
    derive_shared_secret,
    unwrap_onion_packet,
)


def test_shared_secret_derivation():
    sec, pub = generate_keypair()
    ss1 = derive_shared_secret(pub.hex(), str(sec))
    ss2 = derive_shared_secret(pub.hex(), str(sec))
    assert ss1 == ss2
    assert len(ss1) == 32


def test_sphinx_onion_routing_3_hops():
    bob_sec, _bob_pub = generate_keypair()
    dave_sec, _dave_pub = generate_keypair()

    node_keys = {
        "Bob": str(bob_sec),
        "Dave": str(dave_sec),
    }

    # Route: Alice -> Bob -> Dave
    route_hops = [
        ("Bob", "Dave", 25_000, 144),
        ("Dave", "", 25_000, 100),
    ]

    packet = create_onion_packet(route_hops, node_keys)
    assert packet.ephemeral_pubkey != ""
    assert packet.routing_info_hex != ""
    assert packet.hmac_tag != ""

    # Bob unwraps 1st layer
    bob_payload, dave_packet = unwrap_onion_packet(packet, node_wif_key=str(bob_sec))
    assert bob_payload.next_hop == "Dave"
    assert bob_payload.amount_sat == 25_000
    assert bob_payload.locktime == 144
    assert dave_packet is not None

    # Dave unwraps 2nd (final) layer
    dave_payload, final_packet = unwrap_onion_packet(
        dave_packet, node_wif_key=str(dave_sec)
    )
    assert dave_payload.next_hop == ""
    assert dave_payload.amount_sat == 25_000
    assert dave_payload.locktime == 100
    assert final_packet is None


def test_sphinx_hmac_tamper_detection():
    bob_sec, _bob_pub = generate_keypair()
    node_keys = {"Bob": str(bob_sec)}
    route_hops = [("Bob", "", 10_000, 100)]

    packet = create_onion_packet(route_hops, node_keys)

    # Tamper with encrypted routing info
    tampered_packet = SphinxPacket(
        ephemeral_pubkey=packet.ephemeral_pubkey,
        routing_info_hex="00" * (len(packet.routing_info_hex) // 2),
        hmac_tag=packet.hmac_tag,
    )

    with pytest.raises(PaymentCommunityError, match="HMAC integrity check failed"):
        unwrap_onion_packet(tampered_packet, node_wif_key=str(bob_sec))
