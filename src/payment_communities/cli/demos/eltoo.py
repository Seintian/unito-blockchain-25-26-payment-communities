"""
Eltoo (LN-Symmetric) Floating Sequence State Update Protocol Demonstration.
"""

from rich.console import Console

from payment_communities.bitcoin.contracts import ScriptFactory
from payment_communities.domain.node import Node
from payment_communities.network.client import EsploraClient
from payment_communities.protocols.eltoo import (
    EltooState,
    create_eltoo_settlement_transaction,
    create_eltoo_update_transaction,
    validate_eltoo_override,
)


def run_eltoo_demo(nodes: dict[str, Node], esplora: EsploraClient) -> None:
    """Demonstrates Eltoo (LN-Symmetric) state update protocol without penalty revocation secrets."""
    console = Console()
    console.print(
        "\n[bold blue]=== Eltoo (LN-Symmetric) State Update Protocol Demonstration ===[/bold blue]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]
    multisig_script = ScriptFactory.create_multisig_2of2(
        alice_node.pubkey_bytes, bob_node.pubkey_bytes
    )

    alice_txid, alice_vout = esplora.get_utxo_for_node(
        alice_node.pubkey_bytes, alice_node.p2wpkh_address
    )

    state1 = EltooState(
        state_number=1, sender_balance_sat=80_000, receiver_balance_sat=20_000
    )
    state2 = EltooState(
        state_number=2, sender_balance_sat=50_000, receiver_balance_sat=50_000
    )

    console.print(
        "1. Alice & Bob construct Eltoo State #1 (Alice: 80k sat, Bob: 20k sat)."
    )
    console.print(f"  • State #1 Locktime: {state1.locktime}")

    console.print(
        "\n2. Alice & Bob update to Eltoo State #2 (Alice: 50k sat, Bob: 50k sat)."
    )
    console.print(f"  • State #2 Locktime: {state2.locktime}")
    console.print(
        "  • [dim]No revocation secrets needed! State #2 naturally overrides State #1 on-chain.[/dim]"
    )

    if validate_eltoo_override(state1, state2):
        update_tx2 = create_eltoo_update_transaction(
            spending_txid=alice_txid,
            spending_vout=alice_vout,
            state=state2,
            multisig_redeem_script=bytes(multisig_script),
            sec_sender=alice_node.secret,
            sec_receiver=bob_node.secret,
        )
        settle_tx2 = create_eltoo_settlement_transaction(
            update_txid=update_tx2.GetTxid().hex(),
            update_vout=0,
            sender_pubkey_bytes=alice_node.pubkey_bytes,
            receiver_pubkey_bytes=bob_node.pubkey_bytes,
            state=state2,
            multisig_redeem_script=bytes(multisig_script),
            sec_sender=alice_node.secret,
            sec_receiver=bob_node.secret,
        )

        console.print("\n[bold green]✓ ELTOO SYMMETRIC UPDATE COMPLETE![/bold green]")
        console.print(
            f"  [dim]Signed Update TX2 ID:[/dim] {update_tx2.GetTxid().hex()[:24]}..."
        )
        console.print(
            f"  [dim]Signed Settlement TX2 ID:[/dim] {settle_tx2.GetTxid().hex()[:24]}...\n"
        )
