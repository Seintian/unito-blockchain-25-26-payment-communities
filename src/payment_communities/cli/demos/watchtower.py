"""
BOLT #13 Watchtower Autonomous Breach Sweep Demonstration.
"""

from bitcoin.core.script import SIGHASH_ALL, SIGVERSION_WITNESS_V0, SignatureHash
from rich.console import Console

from payment_communities.bitcoin.transaction import (
    create_asymmetric_commitment_transaction,
)
from payment_communities.bitcoin.utils import sign_sighash
from payment_communities.config import (
    DEFAULT_SIMULATION_CAPACITY_SAT,
    DEFAULT_TO_SELF_DELAY_BLOCKS,
)
from payment_communities.domain.node import Node
from payment_communities.network.client import EsploraClient
from payment_communities.protocols.revocation import (
    create_breach_remedy_transaction,
    create_revocable_output_script,
    generate_revocation_secret,
)
from payment_communities.protocols.watchtower import (
    WatchtowerDaemon,
    WatchtowerSession,
)


def run_watchtower_demo(nodes: dict[str, Node], esplora: EsploraClient) -> None:
    """Demonstrates privacy-preserving Watchtower hint registration and autonomous L1 breach sweep."""
    console = Console()
    console.print(
        "\n[bold magenta]=== Watchtower Autonomous Breach Sweep Demonstration ===[/bold magenta]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]
    session = WatchtowerSession()
    daemon = WatchtowerDaemon(session=session)

    alice_txid, alice_vout = esplora.get_utxo_for_node(
        alice_node.pubkey_bytes, alice_node.p2wpkh_address
    )
    _rev_secret_bytes, rev_hash = generate_revocation_secret()

    revocable_script = create_revocable_output_script(
        revocation_pubkey=rev_hash,
        local_pubkey=alice_node.pubkey_bytes,
        to_self_delay=DEFAULT_TO_SELF_DELAY_BLOCKS,
    )
    revoked_tx = create_asymmetric_commitment_transaction(
        funding_txid=alice_txid,
        funding_vout=alice_vout,
        local_pubkey_bytes=alice_node.pubkey_bytes,
        remote_pubkey_bytes=bob_node.pubkey_bytes,
        revocation_pubkey_bytes=rev_hash,
        local_balance_sat=80_000,
        remote_balance_sat=20_000,
    )
    revoked_txid = revoked_tx.GetTxid().hex()

    dummy_wt_tx = create_breach_remedy_transaction(
        revoked_txid=revoked_txid,
        revoked_vout=0,
        sweeper_pubkey_bytes=bob_node.pubkey_bytes,
        amount_sat=DEFAULT_SIMULATION_CAPACITY_SAT,
        revocation_secret_signature=b"\x00" * 70,
        revocable_redeem_script=revocable_script,
    )
    wt_sighash = SignatureHash(
        revocable_script,
        dummy_wt_tx,
        0,
        SIGHASH_ALL,
        amount=DEFAULT_SIMULATION_CAPACITY_SAT,
        sigversion=SIGVERSION_WITNESS_V0,
    )
    real_wt_sig = sign_sighash(bob_node.secret, wt_sighash)

    console.print(
        "1. Bob subscribes to Watchtower service and registers encrypted AES-256-GCM justice payload..."
    )
    hint = session.register_justice_package(
        revoked_txid_hex=revoked_txid,
        sweeper_pubkey_hex=bob_node.pubkey_bytes.hex(),
        amount_sat=DEFAULT_SIMULATION_CAPACITY_SAT,
        revocation_sig_hex=real_wt_sig.hex(),
        revocation_pubkey_hex=rev_hash.hex(),
        local_pubkey_hex=alice_node.pubkey_bytes.hex(),
        to_self_delay=DEFAULT_TO_SELF_DELAY_BLOCKS,
    )

    console.print(f"  • Watchtower stores 16-byte hint key: [cyan]{hint}[/cyan]")
    console.print(
        "  • [dim]Watchtower status: Encrypted AES-256-GCM payload stored. Zero knowledge of keys or contents.[/dim]"
    )

    console.print("\n2. Alice maliciously broadcasts revoked transaction on L1...")
    console.print(f"  • Broadcast TXID: {revoked_txid[:24]}...")

    console.print("\n3. Watchtower scans L1 block stream and identifies hint match!")
    justice_tx = daemon.scan_transaction(revoked_txid)
    if justice_tx:
        console.print(
            "  [bold green]⚡ WATCHTOWER TRIGGERED![/bold green] Decrypted AES-256-GCM payload and broadcast Justice Sweep!"
        )
        console.print(
            f"  [dim]Autonomous Sweep TXID:[/dim] {justice_tx.GetTxid().hex()[:24]}...\n"
        )
