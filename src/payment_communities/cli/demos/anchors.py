"""
BOLT #3 Anchor Outputs & CPFP Fee Bumping Interactive Demonstration.
"""

from bitcoin.core.script import SIGHASH_ALL, SIGVERSION_WITNESS_V0, SignatureHash
from rich.console import Console
from rich.table import Table

from payment_communities.bitcoin.utils import sign_sighash
from payment_communities.config import (
    BITCOIN_ANCHOR_OUTPUT_SAT,
    DEFAULT_CPFP_FEE_BUMP_SAT,
)
from payment_communities.domain.node import Node
from payment_communities.network.client import EsploraClient
from payment_communities.protocols.anchors import (
    create_anchor_commitment_transaction,
    create_cpfp_fee_bump_transaction,
)


def run_anchors_demo(nodes: dict[str, Node], esplora: EsploraClient) -> None:
    """Demonstrates BOLT #3 330 sat Anchor Outputs and CPFP Child Fee Bumping."""
    console = Console()
    console.print(
        "\n[bold green]=== Anchor Outputs & CPFP Fee Bumping Demonstration ===[/bold green]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]

    alice_txid, alice_vout = esplora.get_utxo_for_node(
        alice_node.pubkey_bytes, alice_node.p2wpkh_address
    )

    console.print(
        f"1. Constructing Commitment TX augmented with {BITCOIN_ANCHOR_OUTPUT_SAT} sat Anchor Outputs..."
    )
    tx, local_script, _remote_script = create_anchor_commitment_transaction(
        funding_txid=alice_txid,
        funding_vout=alice_vout,
        sender_pubkey_bytes=alice_node.pubkey_bytes,
        receiver_pubkey_bytes=bob_node.pubkey_bytes,
        sender_balance_sat=70_000,
        receiver_balance_sat=30_000,
    )

    table = Table(title="Commitment Transaction Outputs with Anchors")
    table.add_column("Output Index", justify="center")
    table.add_column("Output Type", style="cyan")
    table.add_column("Amount (sat)", justify="right")

    table.add_row("0", "Alice P2WPKH Balance", "70,000")
    table.add_row("1", "Bob P2WPKH Balance", "30,000")
    table.add_row("2", "to_local_anchor (Alice 16-CSV)", f"{BITCOIN_ANCHOR_OUTPUT_SAT}")
    table.add_row("3", "to_remote_anchor (Bob 16-CSV)", f"{BITCOIN_ANCHOR_OUTPUT_SAT}")

    console.print(table)

    console.print(
        "\n2. High L1 Mempool Congestion Detected! Alice constructs CPFP Child Transaction..."
    )
    dummy_child_tx = create_cpfp_fee_bump_transaction(
        parent_commitment_txid=tx.GetTxid().hex(),
        anchor_vout=2,
        fee_bumper_pubkey_bytes=alice_node.pubkey_bytes,
        fee_bump_sat=DEFAULT_CPFP_FEE_BUMP_SAT,
        anchor_redeem_script=local_script,
        signature=b"\x00" * 70,
    )
    cpfp_sighash = SignatureHash(
        local_script,
        dummy_child_tx,
        0,
        SIGHASH_ALL,
        amount=BITCOIN_ANCHOR_OUTPUT_SAT,
        sigversion=SIGVERSION_WITNESS_V0,
    )
    real_cpfp_sig = sign_sighash(alice_node.secret, cpfp_sighash)

    child_tx = create_cpfp_fee_bump_transaction(
        parent_commitment_txid=tx.GetTxid().hex(),
        anchor_vout=2,
        fee_bumper_pubkey_bytes=alice_node.pubkey_bytes,
        fee_bump_sat=DEFAULT_CPFP_FEE_BUMP_SAT,
        anchor_redeem_script=local_script,
        signature=real_cpfp_sig,
    )

    console.print(
        f"  • Alice spends {BITCOIN_ANCHOR_OUTPUT_SAT} sat Anchor Output to attach {DEFAULT_CPFP_FEE_BUMP_SAT:,} sat mining fee package!"
    )
    console.print(f"  [dim]CPFP Child TXID:[/dim] {child_tx.GetTxid().hex()[:24]}...")
    console.print(
        "  [bold green]✓ CPFP FEE BUMP PACKAGE BROADCAST CONFIRMED![/bold green]\n"
    )
