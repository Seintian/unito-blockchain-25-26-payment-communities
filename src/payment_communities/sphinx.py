"""
Sphinx Onion Encrypted Multi-Hop Packet Routing Engine (Lightning BOLT #4).
Provides privacy-preserving payment routing where intermediate nodes only learn
their immediate predecessor and successor without discovering the full path or ultimate sender/recipient.
"""

import hmac
import json

from pydantic import BaseModel

from payment_communities.bitcoin_utils import (
    generate_keypair,
    hex_to_bytes,
    sha256,
)
from payment_communities.exceptions import PaymentCommunityError


class SphinxPayload(BaseModel):
    """Routing instructions for a single hop along a payment route."""

    next_hop: str
    amount_sat: int
    locktime: int


class SphinxPacket(BaseModel):
    """Encrypted onion packet transmitted between nodes."""

    ephemeral_pubkey: str
    routing_info_hex: str
    hmac_tag: str


def derive_shared_secret(ephemeral_pubkey_hex: str, private_key_wif: str) -> bytes:
    """
    Derives an ECDH shared secret using an ephemeral public key and node private key.
    For simulation, computes sha256(ephemeral_pubkey + private_key_bytes).
    """
    node_secret, _pub = generate_keypair(private_key_wif)
    raw_sec = bytes(node_secret)
    eph_bytes = hex_to_bytes(ephemeral_pubkey_hex)
    return sha256(eph_bytes + raw_sec)


def compute_hmac(key: bytes, data: bytes) -> str:
    """Computes HMAC-SHA256 integrity tag over data."""
    return hmac.new(key, data, hashlib_module="sha256").hexdigest()


def _xor_cipher(data_bytes: bytes, key: bytes) -> bytearray:
    result = bytearray()
    for i, b in enumerate(data_bytes):
        key_byte = key[i % len(key)]
        result.append(b ^ key_byte)
    return result


def create_onion_packet(
    route_hops: list[tuple[str, str, int, int]], node_wif_keys: dict[str, str]
) -> SphinxPacket:
    """
    Constructs a multi-layer encrypted Sphinx onion packet for a payment route.
    route_hops: list of (current_node, next_hop, amount_sat, locktime)
    Envelopes payloads in reverse order (destination payload encrypted deepest).
    """
    _eph_sec, eph_pub = generate_keypair()
    ephemeral_pubkey_hex = eph_pub.hex()

    current_blob = b""
    current_hmac = ""

    # Wrap layers from destination back to sender
    for current_node, next_hop, amount, locktime in reversed(route_hops):
        wif = node_wif_keys.get(current_node, "")
        ss = derive_shared_secret(ephemeral_pubkey_hex, wif if wif else None)

        payload_dict = {
            "next_hop": next_hop,
            "amount_sat": amount,
            "locktime": locktime,
            "inner_blob": current_blob.hex(),
            "inner_hmac": current_hmac,
        }
        payload_bytes = json.dumps(payload_dict).encode("utf-8")
        encrypted_layer = _xor_cipher(payload_bytes, ss)

        import hashlib

        current_hmac = hmac.new(
            ss, bytes(encrypted_layer), digestmod=hashlib.sha256
        ).hexdigest()
        current_blob = bytes(encrypted_layer)

    return SphinxPacket(
        ephemeral_pubkey=ephemeral_pubkey_hex,
        routing_info_hex=current_blob.hex(),
        hmac_tag=current_hmac,
    )


def unwrap_onion_packet(
    packet: SphinxPacket, node_wif_key: str | None = None
) -> tuple[SphinxPayload, SphinxPacket | None]:
    """
    Peels off a single layer of the Sphinx onion packet at an intermediate or final node.
    Returns:
        (SphinxPayload, next_SphinxPacket or None if destination)
    Raises:
        PaymentCommunityError: If HMAC validation fails (packet tampered with).
    """
    ss = derive_shared_secret(packet.ephemeral_pubkey, node_wif_key)

    import hashlib

    blob_bytes = hex_to_bytes(packet.routing_info_hex)
    expected_hmac = hmac.new(ss, blob_bytes, digestmod=hashlib.sha256).hexdigest()

    if expected_hmac != packet.hmac_tag:
        raise PaymentCommunityError(
            "Sphinx HMAC integrity check failed! Onion packet has been tampered with."
        )

    decrypted_bytes = _xor_cipher(blob_bytes, ss)
    payload_dict = json.loads(decrypted_bytes.decode("utf-8"))

    payload = SphinxPayload(
        next_hop=payload_dict["next_hop"],
        amount_sat=payload_dict["amount_sat"],
        locktime=payload_dict["locktime"],
    )

    inner_blob_hex = payload_dict.get("inner_blob", "")
    inner_hmac = payload_dict.get("inner_hmac", "")

    next_packet = None
    if inner_blob_hex and inner_hmac and payload.next_hop:
        next_packet = SphinxPacket(
            ephemeral_pubkey=packet.ephemeral_pubkey,
            routing_info_hex=inner_blob_hex,
            hmac_tag=inner_hmac,
        )

    return payload, next_packet
