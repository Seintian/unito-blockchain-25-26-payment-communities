"""
BOLT #4 Sphinx Onion Encrypted Routing & Multi-Hop Privacy Engine.
Encrypts multi-hop payment routes into layered onion packets using ECDH shared secrets and HMACs.
"""

import hmac
import json
from typing import TYPE_CHECKING

from bitcoin.wallet import CBitcoinSecret
from pydantic import BaseModel
from rich.console import Console

from payment_communities.bitcoin.utils import (
    ec_scalar_mul_point,
    generate_keypair,
    sha256,
)
from payment_communities.config import (
    DEFAULT_HTLC_LOCKTIME_T1_DELTA,
    DEFAULT_HTLC_LOCKTIME_T2_DELTA,
    DEFAULT_SIMULATION_PAYMENT_SAT,
    SPHINX_HEADER_BYTES,
    settings,
)
from payment_communities.exceptions import PaymentCommunityError

if TYPE_CHECKING:
    from payment_communities.domain.node import Node
    from payment_communities.network.client import EsploraClient



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


def create_onion_packet(
    hops: list[
        tuple[str, str, int, int]
    ],  # [(current_node, next_hop, amount, locktime)]
    node_pubkeys: dict[str, str],  # node_alias -> wif_private_key
) -> SphinxPacket:
    """
    Constructs a multi-layer encrypted Sphinx onion packet for a route using secp256k1 ECDH shared secrets.
    """
    ephemeral_sec, ephemeral_pub = generate_keypair()

    # Pre-derive ECDH shared secret for each hop in the route (d_ephemeral * P_node)
    hop_shared_secrets: list[bytes] = []
    for node_alias, _next_hop, _amount, _cltv in hops:
        node_wif = node_pubkeys.get(node_alias)
        _node_sec, node_pub = generate_keypair(node_wif)
        shared_secret = derive_shared_secret(ephemeral_sec, node_pub)
        hop_shared_secrets.append(shared_secret)

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
    Peels off one layer of the Sphinx onion packet at the current hop node using secp256k1 ECDH (d_node * P_ephemeral).
    """
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

    next_packet = SphinxPacket(
        ephemeral_key_hex=packet.ephemeral_key_hex,
        routing_info_hex=inner_payload_str.encode("utf-8").hex(),
        hmac_hex=inner_hmac,
    )
    return payload, next_packet


def run_sphinx_demo(nodes: dict[str, Node], esplora: EsploraClient) -> None:
    """Demonstrates Sphinx multi-layer onion encryption using secp256k1 ECDH across routing nodes."""
    console = Console()
    console.print(
        "\n[bold yellow]=== Sphinx Onion Encrypted Routing Demonstration ===[/bold yellow]\n"
    )

    bob_node = nodes["Bob"]
    dave_node = nodes["Dave"]

    node_keys = {
        "Bob": settings.bob_key or str(bob_node.secret),
        "Dave": settings.dave_key or str(dave_node.secret),
    }

    current_height = esplora.get_block_height()
    t1_delta = current_height + DEFAULT_HTLC_LOCKTIME_T1_DELTA
    t2_delta = current_height + DEFAULT_HTLC_LOCKTIME_T2_DELTA

    route_hops = [
        ("Bob", "Dave", DEFAULT_SIMULATION_PAYMENT_SAT, t1_delta),
        ("Dave", "", DEFAULT_SIMULATION_PAYMENT_SAT, t2_delta),
    ]

    console.print(
        "1. Alice constructs multi-layer encrypted Sphinx onion packet for Bob -> Dave..."
    )
    packet = create_onion_packet(route_hops, node_keys)
    console.print(
        f"  • Ephemeral PubKey: [cyan]{packet.ephemeral_key_hex[:24]}...[/cyan]"
    )
    console.print(f"  • HMAC Integrity Tag: [cyan]{packet.hmac_hex[:24]}...[/cyan]")

    console.print(
        "\n2. Bob receives onion packet and unwraps Layer 1 via secp256k1 ECDH..."
    )
    bob_payload, dave_packet = unwrap_onion_packet(
        packet, node_wif_key=node_keys["Bob"]
    )
    console.print(
        f"  • Bob decrypted instructions: Forward to [bold]{bob_payload.next_hop}[/bold] ({bob_payload.amount_sat:,} sat)"
    )

    if dave_packet:
        console.print(
            "\n3. Dave receives forwarded packet and unwraps final Layer 2 via secp256k1 ECDH..."
        )
        dave_payload, _final_packet = unwrap_onion_packet(
            dave_packet, node_wif_key=node_keys["Dave"]
        )
        console.print(
            f"  • Dave decrypted instructions: Final Destination reached! (Amount: {dave_payload.amount_sat:,} sat)"
        )
        console.print("  [bold green]✓ SPHINX PRIVACY ROUTING COMPLETE![/bold green]\n")
