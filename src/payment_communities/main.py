"""
Payment Communities - Main CLI Starting Point.
Simulates off-chain micropayment channels, Poon-Dryja state revocation,
Dijkstra pathfinding, and persistent state management on Bitcoin Signet/Testnet.
"""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from payment_communities.channel import ChannelState
from payment_communities.config import settings
from payment_communities.contracts import create_htlc_script
from payment_communities.network import EsploraClient
from payment_communities.node import Node
from payment_communities.revocation import (
    create_breach_remedy_transaction,
    create_revocable_output_script,
    generate_revocation_secret,
)
from payment_communities.routing import NetworkGraph
from payment_communities.storage import StorageEngine
from payment_communities.transaction import (
    create_commitment_transaction,
    create_cooperative_close_transaction,
    create_funding_transaction,
)

app = typer.Typer(
    name="Payment Communities",
    help="Bitcoin Micropayment Channels Simulation CLI (Alice -> Bob -> Dave)",
    add_completion=False,
)
console = Console()
storage = StorageEngine()

# Persistent node registry for network simulation
nodes = {
    "Alice": Node("Alice", wif_key=settings.alice_key or None),
    "Bob": Node("Bob", wif_key=settings.bob_key or None),
    "Dave": Node("Dave", wif_key=settings.dave_key or None),
}

esplora = EsploraClient()


def _sync_nodes_with_storage():
    """Loads persistent channels into nodes dictionary."""
    state = storage.load_state()
    for channel in state.channels.values():
        if channel.sender_alias in nodes and channel.receiver_alias in nodes:
            sender = nodes[channel.sender_alias]
            receiver = nodes[channel.receiver_alias]
            sender.channels[receiver.alias] = channel
            receiver.channels[sender.alias] = channel


def _save_nodes_to_storage():
    """Saves current channel states into storage."""
    all_channels = {}
    for node in nodes.values():
        for ch in node.channels.values():
            all_channels[ch.channel_id] = ch
    storage.save_state(all_channels, {})


@app.command()
def info():
    """Displays project setup, network parameter settings, node keys, and on-chain addresses."""
    _sync_nodes_with_storage()
    current_height = esplora.get_block_height()
    console.print(
        Panel.fit(
            "[bold cyan]Payment Communities - Bitcoin Micropayment Channels[/bold cyan]\n"
            f"[green]Network:[/green] {settings.network}\n"
            f"[green]Esplora API:[/green] {settings.esplora_api_url}\n"
            f"[green]Current Block Height:[/green] {current_height}\n"
            f"[green]Storage File:[/green] {storage.file_path}\n\n"
            "[yellow]Node Addresses & Public Keys:[/yellow]\n"
            f"  • Alice: {nodes['Alice'].address} ({nodes['Alice'].pubkey_hex[:16]}...)\n"
            f"  • Bob:   {nodes['Bob'].address} ({nodes['Bob'].pubkey_hex[:16]}...)\n"
            f"  • Dave:  {nodes['Dave'].address} ({nodes['Dave'].pubkey_hex[:16]}...)",
            title="Project Configuration",
        )
    )


@app.command()
def status():
    """Displays active channels, balances, and pending HTLC contracts."""
    _sync_nodes_with_storage()
    table = Table(title="Payment Channels Status Matrix")
    table.add_column("Channel ID", style="cyan")
    table.add_column("Sender", style="magenta")
    table.add_column("Receiver", style="green")
    table.add_column("Capacity (sat)", justify="right")
    table.add_column("Sender Bal (sat)", justify="right")
    table.add_column("Receiver Bal (sat)", justify="right")
    table.add_column("State", style="bold yellow")
    table.add_column("Active HTLCs", justify="center")

    processed_channels = set()

    for node in nodes.values():
        for channel in node.channels.values():
            if channel.channel_id in processed_channels:
                continue
            processed_channels.add(channel.channel_id)
            table.add_row(
                channel.channel_id,
                channel.sender_alias,
                channel.receiver_alias,
                f"{channel.capacity_sat:,}",
                f"{channel.balance_sender_sat:,}",
                f"{channel.balance_receiver_sat:,}",
                channel.state.value,
                str(len(channel.active_htlcs)),
            )

    if not processed_channels:
        console.print(
            "[yellow]No payment channels currently open. Run `simulate` to see a full demo.[/yellow]"
        )
    else:
        console.print(table)


@app.command()
def simulate():
    """Runs an automated multi-hop payment routing simulation with pathfinding and persistence."""
    console.print(
        "\n[bold green]=== Starting Multi-Hop Micropayment Simulation ===[/bold green]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]
    dave_node = nodes["Dave"]

    # 1. Open Off-Chain Channels with Real Funding CMutableTransaction Generation
    console.print(
        "[cyan]Step 1:[/cyan] Opening channel Alice -> Bob (100,000 sat capacity)..."
    )
    ch_ab = alice_node.open_channel(bob_node, capacity_sat=100_000)
    funding_tx_ab, _multisig_script_ab = create_funding_transaction(
        funder_utxo_txid="00" * 32,
        funder_utxo_vout=0,
        funder_pubkey_bytes=alice_node.pubkey_bytes,
        counterparty_pubkey_bytes=bob_node.pubkey_bytes,
        capacity_sat=100_000,
    )
    ch_ab.funding_txid = funding_tx_ab.GetTxid().hex()
    ch_ab.funding_vout = 0
    console.print(
        f"  [dim]Funding TXID (Alice->Bob):[/dim] {(ch_ab.funding_txid or '')[:24]}..."
    )

    console.print(
        "[cyan]Step 2:[/cyan] Opening channel Bob -> Dave (100,000 sat capacity)..."
    )
    ch_bd = bob_node.open_channel(dave_node, capacity_sat=100_000)
    funding_tx_bd, _multisig_script_bd = create_funding_transaction(
        funder_utxo_txid="11" * 32,
        funder_utxo_vout=0,
        funder_pubkey_bytes=bob_node.pubkey_bytes,
        counterparty_pubkey_bytes=dave_node.pubkey_bytes,
        capacity_sat=100_000,
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
    route = graph.find_path("Alice", "Dave", amount_sat=25_000)

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

    # 4. Alice routes HTLC to Bob
    payment_amount_sat = 25_000
    current_block_height = esplora.get_block_height()
    locktime_alice_to_bob = current_block_height + 144
    locktime_bob_to_dave = current_block_height + 100

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

    # Create commitment tx object with HTLC script
    htlc_script_ab = create_htlc_script(
        alice_node.pubkey_bytes,
        bob_node.pubkey_bytes,
        bytes.fromhex(hash_hex),
        locktime_alice_to_bob,
    )
    create_commitment_transaction(
        funding_txid=ch_ab.funding_txid or "",
        funding_vout=0,
        sender_pubkey_bytes=alice_node.pubkey_bytes,
        receiver_pubkey_bytes=bob_node.pubkey_bytes,
        sender_balance_sat=75_000,
        receiver_balance_sat=0,
        htlc_outputs=[(25_000, htlc_script_ab)],
    )
    console.print(
        "  [bold green]✓ HTLC Alice -> Bob offered & Commitment TX built[/bold green]"
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
    console.print("  [bold green]✓ Dave claimed 25,000 sat from Bob![/bold green]")

    console.print(
        "\n[cyan]Step 7:[/cyan] Bob fulfills HTLC with Alice using revealed Preimage..."
    )
    alice_node.fulfill_htlc("Bob", "htlc_ab_1", preimage_hex)
    console.print("  [bold green]✓ Bob claimed 25,000 sat from Alice![/bold green]")

    # 7. Cooperative Close Settlement Transaction Generation
    close_tx_ab = create_cooperative_close_transaction(
        funding_txid=ch_ab.funding_txid or "",
        funding_vout=0,
        sender_pubkey_bytes=alice_node.pubkey_bytes,
        receiver_pubkey_bytes=bob_node.pubkey_bytes,
        final_sender_sat=75_000,
        final_receiver_sat=25_000,
    )
    console.print(
        f"\n[dim]Cooperative Settlement TXID:[/dim] {close_tx_ab.GetTxid().hex()[:24]}..."
    )

    _save_nodes_to_storage()
    console.print(
        "\n[bold green]=== Multi-Hop Payment Complete & State Persisted! ===[/bold green]\n"
    )
    status()


@app.command()
def breach_demo():
    """Demonstrates Poon-Dryja State Revocation and Breach Remedy Justice Sweep Penalty."""
    console.print(
        "\n[bold red]=== Poon-Dryja Breach Remedy Penalty Demonstration ===[/bold red]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]

    console.print(
        "[cyan]1. Setting up Channel Alice -> Bob (100,000 sat capacity)...[/cyan]"
    )
    ch = alice_node.open_channel(bob_node, capacity_sat=100_000)

    rev_secret_bytes, rev_hash = generate_revocation_secret()
    revocable_script = create_revocable_output_script(
        revocation_pubkey=rev_hash,
        local_pubkey=alice_node.pubkey_bytes,
        to_self_delay=144,
    )

    console.print(
        "  • Alice & Bob execute Payment #1 (Alice: 80,000 sat, Bob: 20,000 sat). State #1 is REVOKED."
    )
    ch.revoke_prior_state(1, rev_secret_bytes.hex())

    console.print("  • Current State #2 active (Alice: 50,000 sat, Bob: 50,000 sat).")
    ch.balance_sender_sat = 50_000
    ch.balance_receiver_sat = 50_000

    console.print(
        "\n[bold yellow]⚠️  MALICIOUS ATTEMPT:[/bold yellow] Alice attempts to broadcast revoked State #1 on-chain to steal 80,000 sat!"
    )

    if ch.revocation_store.is_state_revoked(1):
        console.print(
            "  [bold red]🚨 BREACH DETECTED![/bold red] Bob identifies Alice's broadcast as a REVOKED state!"
        )

        revealed_secret = ch.revocation_store.get_revocation_secret(1)
        mock_justice_sig = b"\x30\x44" + b"\x00" * 68

        justice_tx = create_breach_remedy_transaction(
            revoked_txid="aa" * 32,
            revoked_vout=0,
            sweeper_pubkey_bytes=bob_node.pubkey_bytes,
            amount_sat=100_000,
            revocation_secret_signature=mock_justice_sig,
            revocable_redeem_script=revocable_script,
        )

        secret_disp = (revealed_secret or "")[:16]
        console.print(
            f"  [bold green]⚡ BREACH REMEDY EXECUTED![/bold green] Bob uses revealed secret ({secret_disp}...) to sweep 100% of channel capacity!"
        )
        console.print(
            f"  [dim]Justice Sweep TXID:[/dim] {justice_tx.GetTxid().hex()[:24]}..."
        )

        ch.balance_sender_sat = 0
        ch.balance_receiver_sat = 100_000
        ch.state = ChannelState.SETTLED

        console.print(
            "\n[bold green]=== Alice Punished! Final Channel Balances: ===[/bold green]\n"
        )
        console.print(f"  • Alice: {ch.balance_sender_sat:,} sat (PUNISHED: 0 sat)")
        console.print(
            f"  • Bob:   {ch.balance_receiver_sat:,} sat (SWEEPS 100% OF CAPACITY)"
        )


@app.command()
def watchtower_demo():
    """Demonstrates privacy-preserving Watchtower hint registration and autonomous L1 breach sweep."""
    from payment_communities.config import DEFAULT_TO_SELF_DELAY_BLOCKS
    from payment_communities.watchtower import WatchtowerDaemon, WatchtowerSession

    console.print(
        "\n[bold magenta]=== Watchtower Autonomous Breach Sweep Demonstration ===[/bold magenta]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]
    session = WatchtowerSession()
    daemon = WatchtowerDaemon(session=session)

    revoked_txid = "cc" * 32
    mock_sig = b"\x30\x44" + b"\x00" * 68
    _rev_secret_bytes, rev_hash = generate_revocation_secret()

    console.print(
        "1. Bob subscribes to Watchtower service and registers encrypted justice payload..."
    )
    hint = session.register_justice_package(
        revoked_txid_hex=revoked_txid,
        sweeper_pubkey_hex=bob_node.pubkey_bytes.hex(),
        amount_sat=100_000,
        revocation_sig_hex=mock_sig.hex(),
        revocation_pubkey_hex=rev_hash.hex(),
        local_pubkey_hex=alice_node.pubkey_bytes.hex(),
        to_self_delay=DEFAULT_TO_SELF_DELAY_BLOCKS,
    )
    console.print(f"  • Watchtower stores 16-byte hint key: [cyan]{hint}[/cyan]")
    console.print(
        "  • [dim]Watchtower status: Does NOT know channel keys or transaction contents.[/dim]"
    )

    console.print("\n2. Alice maliciously broadcasts revoked transaction on L1...")
    console.print(f"  • Broadcast TXID: {revoked_txid[:24]}...")

    console.print("\n3. Watchtower scans L1 block stream and identifies hint match!")
    justice_tx = daemon.scan_transaction(revoked_txid)
    if justice_tx:
        console.print(
            "  [bold green]⚡ WATCHTOWER TRIGGERED![/bold green] Decrypted payload and broadcast Justice Sweep!"
        )
        console.print(
            f"  [dim]Autonomous Sweep TXID:[/dim] {bytes(justice_tx.GetTxid()).hex()[:24]}...\n"
        )


@app.command()
def eltoo_demo():
    """Demonstrates Eltoo (LN-Symmetric) state update protocol without penalty revocation secrets."""
    from payment_communities.contracts import create_2of2_multisig_script
    from payment_communities.eltoo import (
        EltooState,
        create_eltoo_settlement_transaction,
        create_eltoo_update_transaction,
        validate_eltoo_override,
    )

    console.print(
        "\n[bold blue]=== Eltoo (LN-Symmetric) State Update Protocol Demonstration ===[/bold blue]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]
    multisig_script = create_2of2_multisig_script(
        alice_node.pubkey_bytes, bob_node.pubkey_bytes
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
            spending_txid="00" * 32,
            spending_vout=0,
            state=state2,
            multisig_redeem_script=bytes(multisig_script),
            sig_sender=b"\x00" * 64,
            sig_receiver=b"\x00" * 64,
        )
        settle_tx2 = create_eltoo_settlement_transaction(
            update_txid=bytes(update_tx2.GetTxid()).hex(),
            update_vout=0,
            sender_pubkey_bytes=alice_node.pubkey_bytes,
            receiver_pubkey_bytes=bob_node.pubkey_bytes,
            state=state2,
            sig_sender=b"\x00" * 64,
            sig_receiver=b"\x00" * 64,
            multisig_redeem_script=bytes(multisig_script),
        )

        console.print("\n[bold green]✓ ELTOO SYMMETRIC UPDATE COMPLETE![/bold green]")
        console.print(
            f"  [dim]Update TX2 ID:[/dim] {bytes(update_tx2.GetTxid()).hex()[:24]}..."
        )
        console.print(
            f"  [dim]Settlement TX2 ID:[/dim] {bytes(settle_tx2.GetTxid()).hex()[:24]}...\n"
        )


def main():
    app()


if __name__ == "__main__":
    main()
