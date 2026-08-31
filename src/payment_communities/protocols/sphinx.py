"""
BOLT #4 Sphinx Onion Encrypted Routing & Multi-Hop Privacy Engine.
Encrypts multi-hop payment routes into layered onion packets using ECDH shared secrets and HMACs.
"""

import hmac
import json
from collections.abc import Mapping

from bitcoin.wallet import CBitcoinSecret
from pydantic import BaseModel

from payment_communities.bitcoin.utils import (
    ec_scalar_mul_point,
    generate_keypair,
    sha256,
)
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


def derive_shared_secret(
    sec: CBitcoinSecret | bytes | str, pubkey_bytes: bytes
) -> bytes:
    """
    Derives standard secp256k1 ECDH shared secret: SHA256(d * P).
    Works commutatively for sender (d_ephemeral, P_node) and node (d_node, P_ephemeral).
    """
    if isinstance(sec, str):
        sec_obj = CBitcoinSecret(sec)
        priv_scalar = int.from_bytes(bytes(sec_obj)[:32], "big")
    elif isinstance(sec, bytes):
        priv_scalar = int.from_bytes(sec[:32], "big")
    else:
        priv_scalar = int.from_bytes(bytes(sec)[:32], "big")

    shared_point = ec_scalar_mul_point(priv_scalar, pubkey_bytes)
    return sha256(shared_point)


def compute_hmac(key: bytes, message: bytes) -> str:
    """Computes HMAC-SHA256 digest hex string."""
    return hmac.new(key, message, digestmod="sha256").hexdigest()


def _parse_node_pubkey(val: bytes | str) -> bytes:
    """Helper normalizing pubkey bytes from bytes, hex pubkey, or WIF private key."""
    if isinstance(val, bytes):
        if len(val) == 33:
            return val
        if len(val) == 32:
            return generate_keypair(str(CBitcoinSecret.from_secret_bytes(val)))[1]
    if isinstance(val, str):
        if len(val) == 66:  # 33 bytes in hex
            return bytes.fromhex(val)
        # Try as WIF key
        _sec, pub = generate_keypair(val)
        return pub
    raise ValueError(f"Unable to parse public key from {val}")


def create_onion_packet(
    hops: list[
        tuple[str, str, int, int]
    ],  # [(current_node, next_hop, amount, locktime)]
    node_pubkeys: Mapping[str, bytes | str],  # node_alias -> pubkey (bytes/hex) or WIF
) -> SphinxPacket:
    """
    Constructs a multi-layer encrypted Sphinx onion packet for a route using secp256k1 ECDH
    with per-hop ephemeral key blinding (BOLT #4).
    """
    from payment_communities.bitcoin.utils import (
        ec_point_mul,
        ec_scalar_mul_point,
    )
    from payment_communities.config import SECP256K1_ORDER

    ephemeral_sec, ephemeral_pub = generate_keypair()
    d_current = int.from_bytes(bytes(ephemeral_sec)[:32], "big") % SECP256K1_ORDER
    E_current = ephemeral_pub

    # Pre-derive ECDH shared secrets & blinded ephemeral keys along the forward path
    hop_shared_secrets: list[bytes] = []
    hop_ephemeral_pubs: list[bytes] = []

    for node_alias, _next_hop, _amount, _cltv in hops:
        node_pub = _parse_node_pubkey(node_pubkeys[node_alias])
        hop_ephemeral_pubs.append(E_current)

        shared_secret = sha256(ec_scalar_mul_point(d_current, node_pub))
        hop_shared_secrets.append(shared_secret)

        # Compute per-hop blinding factor b_i = SHA256(E_i || ss_i) mod N
        b_scalar = (
            int.from_bytes(sha256(E_current + shared_secret), "big") % SECP256K1_ORDER
        )
        if b_scalar == 0:
            b_scalar = 1
        d_current = (d_current * b_scalar) % SECP256K1_ORDER
        E_current = ec_point_mul(d_current)

    current_packet_payload = ""
    current_hmac = ""

    # Build onion layers in reverse order (destination -> origin)
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
        ephemeral_key_hex=hop_ephemeral_pubs[0].hex(),
        routing_info_hex=current_packet_payload.encode("utf-8").hex(),
        hmac_hex=current_hmac,
    )


def unwrap_onion_packet(
    packet: SphinxPacket, node_wif_key: str
) -> tuple[SphinxPayload, SphinxPacket | None]:
    """
    Peels off one layer of the Sphinx onion packet at the current hop node using secp256k1 ECDH (d_node * P_ephemeral)
    and blinds the ephemeral key for the next forwarded hop (BOLT #4).
    """
    from payment_communities.bitcoin.utils import ec_scalar_mul_point
    from payment_communities.config import SECP256K1_ORDER

    node_sec, _node_pub = generate_keypair(node_wif_key)
    ephemeral_pub = bytes.fromhex(packet.ephemeral_key_hex)
    shared_secret = derive_shared_secret(node_sec, ephemeral_pub)

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

    # Blind ephemeral public key for the next hop: E_{i+1} = b_i * E_i
    b_scalar = (
        int.from_bytes(sha256(ephemeral_pub + shared_secret), "big") % SECP256K1_ORDER
    )
    if b_scalar == 0:
        b_scalar = 1
    next_ephemeral_pub = ec_scalar_mul_point(b_scalar, ephemeral_pub)

    next_packet = SphinxPacket(
        ephemeral_key_hex=next_ephemeral_pub.hex(),
        routing_info_hex=inner_payload_str.encode("utf-8").hex(),
        hmac_hex=inner_hmac,
    )
    return payload, next_packet
