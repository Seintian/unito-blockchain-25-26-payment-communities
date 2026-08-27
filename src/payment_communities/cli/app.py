"""
Payment Communities - Typer CLI Application Engine.
"""

import httpx
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
from payment_communities.exceptions import NetworkError
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
    try:
        current_height = esplora.get_block_height()
        tip_hash = esplora.get_tip_hash()
        fee_rate = esplora.get_recommended_fee_rate(target_blocks=1)
        network_status = f"[green]Online[/green] (Height: {current_height:,}, Fee: {fee_rate} sat/vB)"
    except (NetworkError, httpx.HTTPError, ValueError) as e:
        tip_hash = "Unavailable"
        network_status = f"[yellow]Degraded ({e})[/yellow]"

    # Query live on-chain balances
    balance_lines = []
    for alias, node in nodes.items():
        try:
            confirmed, unconfirmed = esplora.get_address_balance(node.address)
            bal_str = f"{confirmed:,} sat"
            if unconfirmed:
                bal_str += f" ({unconfirmed:+,} mempool)"
        except NetworkError, httpx.HTTPError, ValueError:
            bal_str = "N/A"
        balance_lines.append(
            f"  • {alias:5}: {node.address}\n"
            f"           [dim]PubKey: {node.pubkey_hex[:24]}... | On-Chain Bal: {bal_str}[/dim]"
        )

    node_info_str = "\n".join(balance_lines)

    console.print(
        Panel.fit(
            "[bold cyan]Payment Communities - Bitcoin Micropayment Channels[/bold cyan]\n"
            f"[green]Network:[/green] {settings.network}\n"
            f"[green]Esplora API:[/green] {settings.esplora_api_url}\n"
            f"[green]Network Status:[/green] {network_status}\n"
            f"[green]Tip Block Hash:[/green] {tip_hash[:32]}...\n"
            f"[green]Signet Faucet:[/green] {settings.signet_faucet_url}\n"
            f"[green]Storage File:[/green] {storage.file_path}\n\n"
            "[yellow]Live Node Addresses, Public Keys & On-Chain Balances:[/yellow]\n"
            f"{node_info_str}",
            title="Project Configuration & Live Network Status",
        )
    )


@app.command()
def funds():
    """Queries and displays live on-chain UTXOs and confirmed balances for all node addresses."""
    console.print(
        "\n[bold cyan]=== Querying Live Test Network UTXOs & Balances ===[/bold cyan]\n"
    )
    table = Table(title=f"Live On-Chain Balances ({settings.network.capitalize()})")
    table.add_column("Node", style="magenta")
    table.add_column("Address", style="cyan")
    table.add_column("Confirmed (sat)", justify="right")
    table.add_column("Mempool (sat)", justify="right")
    table.add_column("UTXO Count", justify="center")

    total_confirmed = 0
    total_mempool = 0

    for alias, node in nodes.items():
        try:
            confirmed, unconfirmed = esplora.get_address_balance(node.address)
            utxos = esplora.get_address_utxos(node.address)
            table.add_row(
                alias,
                node.address,
                f"{confirmed:,}",
                f"{unconfirmed:+,}" if unconfirmed != 0 else "0",
                str(len(utxos)),
            )
            total_confirmed += confirmed
            total_mempool += unconfirmed
        except (NetworkError, httpx.HTTPError, ValueError) as e:
            table.add_row(alias, node.address, "Error", str(e), "0")

    console.print(table)
    console.print(
        f"\n[green]Total Confirmed On-Chain Balance:[/green] {total_confirmed:,} sat"
    )
    if total_confirmed == 0:
        console.print(
            f"\n[yellow]💡 Tip: Need testnet/signet satoshis? Request free coins from the faucet:[/yellow]\n"
            f"   [cyan]{settings.signet_faucet_url}[/cyan]\n"
            f"   Send funds to Alice: [bold]{nodes['Alice'].address}[/bold]\n"
            f"   Send funds to Bob:   [bold]{nodes['Bob'].address}[/bold]\n"
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
