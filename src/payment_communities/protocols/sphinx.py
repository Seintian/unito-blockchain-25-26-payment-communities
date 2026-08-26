"""
BOLT #4 Sphinx Onion Encrypted Routing & Multi-Hop Privacy Engine.
Encrypts multi-hop payment routes into layered onion packets using ECDH shared secrets and HMACs.
"""

import hmac
import json

from pydantic import BaseModel

from payment_communities.bitcoin.utils import generate_keypair, sha256
from payment_communities.config import SPHINX_HEADER_BYTES
from payment_communities.exceptions import PaymentCommunityError


class SphinxPayload(BaseModel):
    next_hop: str
    amount_sat: int
    cltv_locktime: int


class SphinxPacket(BaseModel):
    ephemeral_key_hex: str
    routing_info_hex: str
    hmac_hex: str


def derive_shared_secret(key1_bytes: bytes, key2_bytes: bytes) -> bytes:
    """
    Derives ECDH shared secret = SHA256(sorted([key1, key2])).
    Commutative calculation for sender and receiver public/private keys.
    """
    sorted_keys = sorted([key1_bytes, key2_bytes])
    return sha256(sorted_keys[0] + sorted_keys[1])


def compute_hmac(key: bytes, message: bytes) -> str:
    """Computes HMAC-SHA256 digest hex string."""
    return hmac.new(key, message, digestmod="sha256").hexdigest()


def create_onion_packet(
    hops: list[
        tuple[str, str, int, int]
    ],  # [(current_node, next_hop, amount, locktime)]
    node_pubkeys: dict[str, str],  # node_alias -> wif_private_key
) -> SphinxPacket:
    """
    Constructs a multi-layer encrypted Sphinx onion packet for a route.
    """
    _ephemeral_sec, ephemeral_pub = generate_keypair()

    # Pre-derive shared secret for each hop in the route
    hop_shared_secrets: list[bytes] = []
    for node_alias, _next_hop, _amount, _cltv in hops:
        node_wif = node_pubkeys.get(node_alias)
        _node_sec, node_pub = generate_keypair(node_wif)
        hop_shared_secrets.append(derive_shared_secret(ephemeral_pub, node_pub))

    current_packet_payload = ""
    current_hmac = ""

    # Build layers in reverse order (destination -> origin)
    for i in reversed(range(len(hops))):
        _node_alias, next_hop, amount, cltv = hops[i]
        shared_secret = hop_shared_secrets[i]

        payload = SphinxPayload(
            next_hop=next_hop, amount_sat=amount, cltv_locktime=cltv
        )
        layer_data = {
            "payload": payload.model_dump(),
            "inner": current_packet_payload,
            "inner_hmac": current_hmac,
        }
        current_packet_payload = json.dumps(layer_data)
        current_hmac = compute_hmac(
            shared_secret, current_packet_payload.encode("utf-8")
        )[: SPHINX_HEADER_BYTES * 2]

    return SphinxPacket(
        ephemeral_key_hex=ephemeral_pub.hex(),
        routing_info_hex=current_packet_payload.encode("utf-8").hex(),
        hmac_hex=current_hmac,
    )


def unwrap_onion_packet(
    packet: SphinxPacket, node_wif_key: str
) -> tuple[SphinxPayload, SphinxPacket | None]:
    """
    Peels off one layer of the Sphinx onion packet at the current hop node.
    """
    _node_sec, node_pub = generate_keypair(node_wif_key)
    ephemeral_pub = bytes.fromhex(packet.ephemeral_key_hex)
    shared_secret = derive_shared_secret(node_pub, ephemeral_pub)

    packet_bytes = bytes.fromhex(packet.routing_info_hex)
    expected_hmac = compute_hmac(shared_secret, packet_bytes)[: SPHINX_HEADER_BYTES * 2]

    if packet.hmac_hex != expected_hmac:
        raise PaymentCommunityError(
            "HMAC integrity check failed! Onion packet was tampered with or corrupted."
        )

    layer_data = json.loads(packet_bytes.decode("utf-8"))
    payload = SphinxPayload(**layer_data["payload"])
    inner_payload_str = layer_data["inner"]
    inner_hmac = layer_data.get("inner_hmac", "")

    if not inner_payload_str:
        return payload, None

    next_packet = SphinxPacket(
        ephemeral_key_hex=packet.ephemeral_key_hex,
        routing_info_hex=inner_payload_str.encode("utf-8").hex(),
        hmac_hex=inner_hmac,
    )
    return payload, next_packet
