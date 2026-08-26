"""
Payment Communities - Typer CLI Application Engine.
"""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from payment_communities.cli.demos import (
    run_anchors_demo,
    run_breach_demo,
    run_eltoo_demo,
    run_ptlc_demo,
    run_simulate_demo,
    run_sphinx_demo,
    run_swaps_demo,
    run_watchtower_demo,
)
from payment_communities.config import settings
from payment_communities.domain.node import Node
from payment_communities.network.client import EsploraClient
from payment_communities.storage.engine import StorageEngine

app = typer.Typer(
    name="Payment Communities",
    help="Bitcoin Micropayment Channels Simulation CLI (Alice -> Bob -> Dave)",
    add_completion=True,
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
    run_simulate_demo(nodes, esplora, status, _save_nodes_to_storage)


@app.command()
def breach_demo():
    """Demonstrates Poon-Dryja State Revocation and Breach Remedy Justice Sweep Penalty."""
    run_breach_demo(nodes)


@app.command()
def watchtower_demo():
    """Demonstrates privacy-preserving Watchtower hint registration and autonomous L1 breach sweep."""
    run_watchtower_demo(nodes)


@app.command()
def eltoo_demo():
    """Demonstrates Eltoo (LN-Symmetric) state update protocol without penalty revocation secrets."""
    run_eltoo_demo(nodes)


@app.command()
def sphinx_demo():
    """Demonstrates Sphinx multi-layer onion encryption across intermediate routing nodes."""
    run_sphinx_demo(nodes)


@app.command()
def ptlc_demo():
    """Demonstrates Point Time-Locked Contracts (PTLCs) and Schnorr Adaptor Signatures."""
    run_ptlc_demo(nodes)


@app.command()
def anchors_demo():
    """Demonstrates BOLT #3 330 sat Anchor Outputs and CPFP Child Fee Bumping."""
    run_anchors_demo(nodes)


@app.command()
def swaps_demo():
    """Demonstrates Atomic Submarine Swaps (L1 <-> L2) and BOLT #7 Liquidity Advertisements."""
    run_swaps_demo(nodes)


def main():
    app()


if __name__ == "__main__":
    main()
