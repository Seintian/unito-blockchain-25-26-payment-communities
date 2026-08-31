"""
Point Time-Locked Contracts (PTLCs) & Schnorr Adaptor Signatures Demonstration.
"""

from rich.console import Console

from payment_communities.bitcoin.utils import ec_point_mul, generate_secret
from payment_communities.domain.node import Node
from payment_communities.network.client import EsploraClient
from payment_communities.protocols.ptlc import (
    adapt_signature,
    create_adaptor_signature,
    extract_adaptor_secret,
    verify_adaptor_signature,
)


def run_ptlc_demo(nodes: dict[str, Node], esplora: EsploraClient) -> None:
    """Demonstrates Point Time-Locked Contracts (PTLCs) and Schnorr Adaptor Signatures."""
    console = Console()
    console.print(
        "\n[bold cyan]=== PTLC & Adaptor Signature Demonstration ===[/bold cyan]\n"
    )

    alice_node = nodes["Alice"]
    secret_scalar_bytes, msg_hash = generate_secret()
    secret_scalar_int = int.from_bytes(secret_scalar_bytes, "big")
    payment_point = ec_point_mul(secret_scalar_int)

    console.print("1. Dave generates payment point T = t * G and sends to Alice...")
    console.print(f"  • Payment Point (T): {payment_point.hex()[:24]}...")

    console.print(
        "\n2. Alice creates Schnorr Adaptor Signature (s') encrypted under T..."
    )
    adaptor_sig = create_adaptor_signature(alice_node.secret, payment_point, msg_hash)
    assert verify_adaptor_signature(adaptor_sig, alice_node.pubkey_bytes, msg_hash)
    console.print(f"  • Adaptor s': {adaptor_sig.s_prime_hex[:24]}...")

    console.print("\n3. Dave adapts signature using secret scalar t (s = s' + t)...")
    final_sig = adapt_signature(adaptor_sig, secret_scalar_bytes)
    console.print(
        f"  • Final On-Chain Witness Signature (s): {final_sig.hex()[:24]}..."
    )

    console.print(
        "\n4. Alice observes s on-chain and extracts secret scalar t (t = s - s')..."
    )
    extracted_secret_bytes = extract_adaptor_secret(adaptor_sig, final_sig)
    assert extracted_secret_bytes == secret_scalar_bytes
    console.print(
        "  [bold green]⚡ PTLC ADAPTOR SECRET EXTRACTED CONFIRMED![/bold green]\n"
    )
