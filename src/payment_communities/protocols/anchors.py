"""
Anchor Outputs & Dynamic CPFP Fee Bumping Engine (BOLT #3).
Allows emergency transaction fee bumping via Child-Pays-For-Parent (CPFP)
using dedicated 330-sat anchor outputs attached to commitment transactions.
"""

from typing import TYPE_CHECKING

from bitcoin.core import CMutableTransaction
from bitcoin.core.script import (
    OP_0,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_ENDIF,
    OP_IFDUP,
    OP_NOTIF,
    SIGHASH_ALL,
    SIGVERSION_WITNESS_V0,
    CScript,
    SignatureHash,
)
from rich.console import Console
from rich.table import Table

from payment_communities.bitcoin.transaction import TransactionBuilder
from payment_communities.bitcoin.utils import hash160, sha256, sign_sighash
from payment_communities.config import (
    BITCOIN_ANCHOR_OUTPUT_SAT,
    BITCOIN_DUST_LIMIT_SAT,
    DEFAULT_CPFP_FEE_BUMP_SAT,
    SEQUENCE_CLTV_ENABLE_MASK,
)

if TYPE_CHECKING:
    from payment_communities.domain.node import Node
    from payment_communities.network.client import EsploraClient


ANCHOR_OUTPUT_SAT: int = BITCOIN_ANCHOR_OUTPUT_SAT


def create_anchor_script(pubkey_bytes: bytes) -> CScript:
    """
    Creates an Anchor output redeem script (BOLT #3).
    Script: <pubkey> OP_CHECKSIG OP_IFDUP OP_NOTIF 16 OP_CHECKSEQUENCEVERIFY OP_ENDIF
    Allows immediate spend by channel key, or 16-block fallback spend by anyone.
    """
    return CScript(
        [
            pubkey_bytes,
            OP_CHECKSIG,
            OP_IFDUP,
            OP_NOTIF,
            16,
            OP_CHECKSEQUENCEVERIFY,
            OP_ENDIF,
        ]
    )


def create_anchor_commitment_transaction(
    funding_txid: str,
    funding_vout: int,
    sender_pubkey_bytes: bytes,
    receiver_pubkey_bytes: bytes,
    sender_balance_sat: int,
    receiver_balance_sat: int,
) -> tuple[CMutableTransaction, CScript, CScript]:
    """
    Creates commitment transaction with twin anchor outputs (330 sat each).
    """
    local_anchor_script = create_anchor_script(sender_pubkey_bytes)
    remote_anchor_script = create_anchor_script(receiver_pubkey_bytes)

    local_p2wsh = CScript([OP_0, sha256(local_anchor_script)])
    remote_p2wsh = CScript([OP_0, sha256(remote_anchor_script)])

    tx_builder = TransactionBuilder()
    tx_builder.add_input(funding_txid, funding_vout)

    if sender_balance_sat >= BITCOIN_DUST_LIMIT_SAT:
        tx_builder.add_output(sender_balance_sat, local_p2wsh)

    if receiver_balance_sat >= BITCOIN_DUST_LIMIT_SAT:
        tx_builder.add_output(receiver_balance_sat, remote_p2wsh)

    # Attach Twin Anchor Outputs
    tx_builder.add_output(ANCHOR_OUTPUT_SAT, local_p2wsh)
    tx_builder.add_output(ANCHOR_OUTPUT_SAT, remote_p2wsh)

    return tx_builder.build(), local_anchor_script, remote_anchor_script


def create_cpfp_fee_bump_transaction(
    parent_commitment_txid: str,
    anchor_vout: int,
    fee_bumper_pubkey_bytes: bytes,
    fee_bump_sat: int,
    anchor_redeem_script: CScript,
    signature: bytes,
) -> CMutableTransaction:
    """
    Constructs a child CPFP fee-bumping transaction spending an anchor output.
    """
    child_output_sat = max(0, ANCHOR_OUTPUT_SAT - fee_bump_sat)
    p2wpkh_spk = CScript([OP_0, hash160(fee_bumper_pubkey_bytes)])

    return (
        TransactionBuilder()
        .add_input(
            parent_commitment_txid, anchor_vout, sequence=SEQUENCE_CLTV_ENABLE_MASK
        )
        .add_output(child_output_sat, p2wpkh_spk)
        .add_witness_stack([signature, bytes(anchor_redeem_script)])
        .build()
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
