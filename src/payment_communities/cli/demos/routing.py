"""
Multi-Hop Payment Routing & Dijkstra Pathfinding Interactive Simulation.
"""

from collections.abc import Callable
from typing import Any

from bitcoin.core.script import SIGHASH_ALL, SIGVERSION_WITNESS_V0, SignatureHash
from rich.console import Console

from payment_communities.bitcoin.contracts import ScriptFactory
from payment_communities.bitcoin.transaction import (
    TransactionBuilder,
    create_commitment_transaction,
    create_cooperative_close_transaction,
    create_funding_transaction,
    sign_commitment_transaction,
)
from payment_communities.bitcoin.utils import sign_sighash
from payment_communities.config import (
    DEFAULT_HTLC_LOCKTIME_T1_DELTA,
    DEFAULT_HTLC_LOCKTIME_T2_DELTA,
    DEFAULT_SIMULATION_CAPACITY_SAT,
    DEFAULT_SIMULATION_PAYMENT_SAT,
)
from payment_communities.domain.node import Node
from payment_communities.network.client import EsploraClient
from payment_communities.network.routing import NetworkGraph


def run_simulate_demo(
    nodes: dict[str, Node],
    esplora: EsploraClient,
    status_fn: Callable[[], Any],
    save_fn: Callable[[], Any],
) -> None:
    """Runs an automated multi-hop payment routing simulation with pathfinding and persistence."""
    console = Console()
    console.print(
        "\n[bold green]=== Starting Multi-Hop Micropayment Simulation ===[/bold green]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]
    dave_node = nodes["Dave"]

    # 1. Fetch live network parameters and UTXOs
    alice_txid, alice_vout = esplora.get_utxo_for_node(
        alice_node.pubkey_bytes, alice_node.p2wpkh_address
    )
    bob_txid, bob_vout = esplora.get_utxo_for_node(
        bob_node.pubkey_bytes, bob_node.p2wpkh_address
    )

    console.print(
        f"[cyan]Step 1:[/cyan] Opening channel Alice -> Bob ({DEFAULT_SIMULATION_CAPACITY_SAT:,} sat capacity)..."
    )
    ch_ab = alice_node.open_channel(
        bob_node, capacity_sat=DEFAULT_SIMULATION_CAPACITY_SAT
    )
    funding_tx_ab, multisig_script_ab = create_funding_transaction(
        funder_utxo_txid=alice_txid,
        funder_utxo_vout=alice_vout,
        funder_pubkey_bytes=alice_node.pubkey_bytes,
        counterparty_pubkey_bytes=bob_node.pubkey_bytes,
        capacity_sat=DEFAULT_SIMULATION_CAPACITY_SAT,
    )
    ch_ab.funding_txid = funding_tx_ab.GetTxid().hex()
    ch_ab.funding_vout = 0
    console.print(
        f"  [dim]Funding TXID (Alice->Bob):[/dim] {(ch_ab.funding_txid or '')[:24]}..."
    )

    console.print(
        f"[cyan]Step 2:[/cyan] Opening channel Bob -> Dave ({DEFAULT_SIMULATION_CAPACITY_SAT:,} sat capacity)..."
    )
    ch_bd = bob_node.open_channel(
        dave_node, capacity_sat=DEFAULT_SIMULATION_CAPACITY_SAT
    )
    funding_tx_bd, _multisig_script_bd = create_funding_transaction(
        funder_utxo_txid=bob_txid,
        funder_utxo_vout=bob_vout,
        funder_pubkey_bytes=bob_node.pubkey_bytes,
        counterparty_pubkey_bytes=dave_node.pubkey_bytes,
        capacity_sat=DEFAULT_SIMULATION_CAPACITY_SAT,
    )
    ch_bd.funding_txid = funding_tx_bd.GetTxid().hex()
    ch_bd.funding_vout = 0
    console.print(
        f"  [dim]Funding TXID (Bob->Dave):[/dim] {(ch_bd.funding_txid or '')[:24]}..."
    )

    # 2. Dijkstra Pathfinding
    graph = NetworkGraph()
    graph.add_channel(ch_ab)
    graph.add_channel(ch_bd)
    route = graph.find_path("Alice", "Dave", amount_sat=DEFAULT_SIMULATION_PAYMENT_SAT)

    console.print(
        f"\n[cyan]Pathfinding Route Found:[/cyan] {' -> '.join(route.path)} "
        f"(Total Sat: {route.total_amount_sat:,}, Total Routing Fee: {route.total_fee_sat:,} sat)"
    )

    # 3. Dave creates invoice (preimage R & hash H)
    console.print(
        "\n[cyan]Step 3:[/cyan] Dave generates invoice (Preimage & Payment Hash)..."
    )
    preimage_hex, hash_hex = dave_node.create_invoice()
    console.print(f"  [dim]Preimage (R):[/dim] {preimage_hex[:24]}...")
    console.print(f"  [dim]Payment Hash (H):[/dim] {hash_hex[:24]}...")

    # 4. Alice routes HTLC to Bob using live block height
    payment_amount_sat = DEFAULT_SIMULATION_PAYMENT_SAT
    current_block_height = esplora.get_block_height()
    locktime_alice_to_bob = current_block_height + DEFAULT_HTLC_LOCKTIME_T1_DELTA
    locktime_bob_to_dave = current_block_height + DEFAULT_HTLC_LOCKTIME_T2_DELTA

    console.print(
        f"\n[cyan]Step 4:[/cyan] Alice locks {payment_amount_sat:,} sat HTLC to Bob..."
    )
    alice_node.route_htlc_payment(
        target_peer_alias="Bob",
        amount_sat=payment_amount_sat,
        payment_hash=hash_hex,
        locktime=locktime_alice_to_bob,
        htlc_id="htlc_ab_1",
    )

    htlc_script_ab = ScriptFactory.create_htlc(
        alice_node.pubkey_bytes,
        bob_node.pubkey_bytes,
        bytes.fromhex(hash_hex),
        locktime_alice_to_bob,
    )
    alice_balance_sat = DEFAULT_SIMULATION_CAPACITY_SAT - payment_amount_sat
    commit_tx_ab = create_commitment_transaction(
        funding_txid=ch_ab.funding_txid or "",
        funding_vout=0,
        sender_pubkey_bytes=alice_node.pubkey_bytes,
        receiver_pubkey_bytes=bob_node.pubkey_bytes,
        sender_balance_sat=alice_balance_sat,
        receiver_balance_sat=0,
        htlc_outputs=[(payment_amount_sat, htlc_script_ab)],
    )
    sign_commitment_transaction(
        tx=commit_tx_ab,
        input_index=0,
        redeem_script=multisig_script_ab,
        capacity_sat=DEFAULT_SIMULATION_CAPACITY_SAT,
        sec1=alice_node.secret,
        sec2=bob_node.secret,
    )
    console.print(
        "  [bold green]✓ HTLC Alice -> Bob offered & Signed Commitment TX built[/bold green]"
    )

    # 5. Bob forwards HTLC to Dave
    console.print(
        f"\n[cyan]Step 5:[/cyan] Bob forwards {payment_amount_sat:,} sat HTLC to Dave..."
    )
    bob_node.route_htlc_payment(
        target_peer_alias="Dave",
        amount_sat=payment_amount_sat,
        payment_hash=hash_hex,
        locktime=locktime_bob_to_dave,
        htlc_id="htlc_bd_1",
    )
    console.print("  [bold green]✓ HTLC Bob -> Dave offered successfully[/bold green]")

    # 6. Preimage Fulfillment across the route
    console.print(
        "\n[cyan]Step 6:[/cyan] Dave fulfills HTLC with Bob using secret Preimage..."
    )
    bob_node.fulfill_htlc("Dave", "htlc_bd_1", preimage_hex)
    console.print(
        f"  [bold green]✓ Dave claimed {payment_amount_sat:,} sat from Bob![/bold green]"
    )

    console.print(
        "\n[cyan]Step 7:[/cyan] Bob fulfills HTLC with Alice using revealed Preimage..."
    )
    alice_node.fulfill_htlc("Bob", "htlc_ab_1", preimage_hex)
    console.print(
        f"  [bold green]✓ Bob claimed {payment_amount_sat:,} sat from Alice![/bold green]"
    )

    # 7. Real Cooperative Close Settlement Transaction Generation & Signing
    close_tx_ab = create_cooperative_close_transaction(
        funding_txid=ch_ab.funding_txid or "",
        funding_vout=0,
        sender_pubkey_bytes=alice_node.pubkey_bytes,
        receiver_pubkey_bytes=bob_node.pubkey_bytes,
        final_sender_sat=alice_balance_sat,
        final_receiver_sat=payment_amount_sat,
    )
    sighash_close = SignatureHash(
        multisig_script_ab,
        close_tx_ab,
        0,
        SIGHASH_ALL,
        amount=DEFAULT_SIMULATION_CAPACITY_SAT,
        sigversion=SIGVERSION_WITNESS_V0,
    )
    sig1_close = sign_sighash(alice_node.secret, sighash_close)
    sig2_close = sign_sighash(bob_node.secret, sighash_close)
    witness_close = ScriptFactory.witness_multisig_2of2(
        sig1_close, sig2_close, multisig_script_ab
    )

    signed_close_tx_ab = (
        TransactionBuilder()
        .add_input(ch_ab.funding_txid or "", 0)
        .add_p2wsh_output(alice_balance_sat, alice_node.pubkey_bytes)
        .add_p2wsh_output(payment_amount_sat, bob_node.pubkey_bytes)
        .add_witness_stack(witness_close)
        .build()
    )

    console.print(
        f"\n[dim]Signed Cooperative Settlement TXID:[/dim] {signed_close_tx_ab.GetTxid().hex()[:24]}..."
    )

    save_fn()
    console.print(
        "\n[bold green]=== Multi-Hop Payment Complete & State Persisted! ===[/bold green]\n"
    )
    status_fn()
