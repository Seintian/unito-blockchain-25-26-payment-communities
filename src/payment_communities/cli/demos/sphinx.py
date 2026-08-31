"""
BOLT #4 Sphinx Onion Encrypted Routing Demonstration.
"""

from rich.console import Console

from payment_communities.config import (
    DEFAULT_HTLC_LOCKTIME_T1_DELTA,
    DEFAULT_HTLC_LOCKTIME_T2_DELTA,
    DEFAULT_SIMULATION_PAYMENT_SAT,
)
from payment_communities.domain.node import Node
from payment_communities.network.client import EsploraClient
from payment_communities.protocols.sphinx import (
    create_onion_packet,
    unwrap_onion_packet,
)


def run_sphinx_demo(nodes: dict[str, Node], esplora: EsploraClient) -> None:
    """Demonstrates Sphinx multi-layer onion encryption using secp256k1 ECDH across routing nodes."""
    console = Console()
    console.print(
        "\n[bold yellow]=== Sphinx Onion Encrypted Routing Demonstration ===[/bold yellow]\n"
    )

    bob_node = nodes["Bob"]
    dave_node = nodes["Dave"]

    node_pubkeys = {
        "Bob": bob_node.pubkey_bytes,
        "Dave": dave_node.pubkey_bytes,
    }

    current_height = esplora.get_block_height()
    t1_delta = current_height + DEFAULT_HTLC_LOCKTIME_T1_DELTA
    t2_delta = current_height + DEFAULT_HTLC_LOCKTIME_T2_DELTA

    route_hops = [
        ("Bob", "Dave", DEFAULT_SIMULATION_PAYMENT_SAT, t1_delta),
        ("Dave", "", DEFAULT_SIMULATION_PAYMENT_SAT, t2_delta),
    ]

    console.print(
        "1. Alice constructs multi-layer encrypted Sphinx onion packet for Bob -> Dave (using public keys only)..."
    )
    packet = create_onion_packet(route_hops, node_pubkeys)
    console.print(
        f"  • Hop 1 Ephemeral PubKey (E0): [cyan]{packet.ephemeral_key_hex[:24]}...[/cyan]"
    )
    console.print(f"  • HMAC Integrity Tag: [cyan]{packet.hmac_hex[:24]}...[/cyan]")

    console.print(
        "\n2. Bob receives onion packet and unwraps Layer 1 via secp256k1 ECDH..."
    )
    bob_payload, dave_packet = unwrap_onion_packet(
        packet, node_wif_key=str(bob_node.secret)
    )
    console.print(
        f"  • Bob decrypted instructions: Forward to [bold]{bob_payload.next_hop}[/bold] ({bob_payload.amount_sat:,} sat)"
    )

    if dave_packet:
        console.print(
            f"  • Blinded Hop 2 Ephemeral PubKey (E1 != E0): [cyan]{dave_packet.ephemeral_key_hex[:24]}...[/cyan]"
        )
        console.print(
            "\n3. Dave receives forwarded packet and unwraps final Layer 2 via secp256k1 ECDH..."
        )
        dave_payload, _final_packet = unwrap_onion_packet(
            dave_packet, node_wif_key=str(dave_node.secret)
        )
        console.print(
            f"  • Dave decrypted instructions: Final Destination reached! (Amount: {dave_payload.amount_sat:,} sat)"
        )
        console.print("  [bold green]✓ SPHINX PRIVACY ROUTING COMPLETE![/bold green]\n")
